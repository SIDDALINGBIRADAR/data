#basic imports
import base64
import json
import logging
import signal
import time
import atexit
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote_plus, urlparse
from contextlib import contextmanager

# Third-party imports
import pandas as pd
import numpy as np
import pendulum
import psycopg2
from psycopg2 import pool, sql
from psycopg2.extras import execute_values
import tink
from tink import aead, cleartext_keyset_handle
from tenacity import retry, stop_after_attempt, wait_exponential

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - memory tracking disabled")

# Airflow imports
from airflow.sdk import dag, task
from airflow.sdk.exceptions import AirflowException, AirflowRuntimeError
from airflow.sdk.bases.hook import BaseHook
from airflow.sdk import Variable


def get_var(key: str, default=None, deserialize_json: bool = False):
    """
    Safe wrapper for airflow.sdk.Variable.get()

    - Returns default if variable is missing
    - Keeps SDK strictness without breaking DAG parse
    """
    try:
        return Variable.get(key, deserialize_json=deserialize_json)
    except AirflowRuntimeError:
        return default


# =====================================================================================
# ============================ CONFIGURATION CONSTANTS ================================
# =====================================================================================

# Default chunk sizes optimized for sequential processing
DEFAULT_READ_CHUNK_SIZE = 15000  # Read 15K rows per iteration
DEFAULT_WRITE_CHUNK_SIZE = 10000  # Write 10K rows per transaction

# Watermark overlap in minutes to prevent data loss
WATERMARK_OVERLAP_MINUTES = 10

# Marker value indicating decryption failure
DECRYPTION_FAILED_MARKER = "[DECRYPTION_FAILED]"

# Concurrent run check window
CONCURRENT_RUN_CHECK_HOURS = 6

# Retry configuration
MAX_RETRY_ATTEMPTS = 3
RETRY_WAIT_MULTIPLIER = 1

# =====================================================================================
# ============================ TABLE CONFIGURATION ====================================
# =====================================================================================

TABLE_CONFIGS = {
    "identities": {
        "columns": [
            "id",
            "org_id",
            "login_id",
            "e_legal_name",
            "e_meta_data",
            "e_primary_email",
            "last_login_at",
            "created_at",
            "status",
            "e_primary_phone",
            "user_group",
            "last_login_failure_at",
            "blocked_status_code",
            "updated_at",
            "e_customer_number",
            "first_login_at",
            "last_login_location",
            "created_by",
        ],
        "encrypted_columns": [
            "e_legal_name",
            "e_meta_data",
            "e_primary_email",
            "e_primary_phone",
            "e_customer_number",
        ],
        "id_column": "id",
        "watermark_column": "updated_at",
        "json_columns": [],
        "description": "User identity records with PII (5 encrypted fields)",
    },
    "mapped_user_application": {
        "columns": [
            "id",
            "application_code",
            "created_by",
            "role_details",
            "identity_id",
            "login_id",
            "org_id",
            "updated_at",
        ],
        "encrypted_columns": [],
        "id_column": "id",
        "watermark_column": "updated_at",
        "json_columns": ["role_details"],
        "description": "User-application role mappings",
    },
    "credentials": {
        "columns": ["id", "failure_count", "identity_id", "updated_at"],
        "encrypted_columns": [],
        "id_column": "id",
        "watermark_column": "updated_at",
        "json_columns": [],
        "description": "Login credentials and failure tracking",
    },
    "identity_device_profile": {
        "columns": ["id", "device_id", "status", "identity_id", "updated_at"],
        "encrypted_columns": [],
        "id_column": "id",
        "watermark_column": "updated_at",
        "json_columns": [],
        "description": "Device profiles for MFA",
    },
    "identity_contact_details": {
        "columns": ["identity_id", "address_detail", "updated_at"],
        "encrypted_columns": ["address_detail"],
        "id_column": "identity_id", 
        "watermark_column": "updated_at",
        "json_columns": [],
        "description": "Contact address details for identities",
    },
}

# Immutable set of allowed tables
ALLOWED_TABLES = frozenset(TABLE_CONFIGS.keys())

# PostgreSQL data type mapping
PG_TYPE_MAP = {
    "character varying": "TEXT",
    "varchar": "TEXT",
    "text": "TEXT",
    "integer": "INTEGER",
    "bigint": "BIGINT",
    "smallint": "SMALLINT",
    "serial": "INTEGER",
    "bigserial": "BIGINT",
    "boolean": "BOOLEAN",
    "bool": "BOOLEAN",
    "timestamp without time zone": "TIMESTAMPTZ",
    "timestamp with time zone": "TIMESTAMPTZ",
    "timestamptz": "TIMESTAMPTZ",
    "date": "DATE",
    "double precision": "DOUBLE PRECISION",
    "real": "REAL",
    "numeric": "NUMERIC",
    "decimal": "NUMERIC",
    "jsonb": "JSONB",
    "json": "JSONB",
    "uuid": "UUID",
    "bytea": "BYTEA",
}

# =====================================================================================
# ============================ LOGGING SETUP ==========================================
# =====================================================================================

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# =====================================================================================
# ============================ MAIN ETL CLASS =========================================
# =====================================================================================


class TinkETL:
    def __init__(
        self,
        caas_kms_uri: str,
        keyset_data: str,
        source_conn_str: str,
        target_conn_str: str,
        chunk_size: int = DEFAULT_WRITE_CHUNK_SIZE,
        read_chunk_size: int = DEFAULT_READ_CHUNK_SIZE,
    ):
        """Initialize ETL processor with encryption and database connections."""
        self.fixed_chunk_size = chunk_size
        self.read_chunk_size = read_chunk_size
        self._shutdown_requested = False

        # Validate inputs
        self._validate_inputs(
            caas_kms_uri, keyset_data, source_conn_str, target_conn_str
        )

        # Initialize Google Tink encryption
        self._initialize_tink(caas_kms_uri, keyset_data)

        # Clear encryption keys from memory
        del caas_kms_uri
        del keyset_data

        # Enhance connection strings
        self.source_conn_str = self._enhance_conn_str(source_conn_str)
        self.target_conn_str = self._enhance_conn_str(target_conn_str)

        # Initialize connection pools
        self._initialize_connection_pools()

        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        # Register cleanup handler
        atexit.register(self._cleanup_pools)


        logger.info(
            "TinkETL initialized successfully | "
            "read_chunk_size=%s | write_chunk_size=%s | dlq_version=%s | schema_agnostic=%s",
            self.read_chunk_size,
            self.fixed_chunk_size,
            "1.0_json_payload",
            True,
        )
        
    def _validate_inputs(self, *args):
        """Validate that all required input parameters are non-empty strings."""
        for i, arg in enumerate(args, 1):
            if not arg or not isinstance(arg, str):
                raise ValueError(
                    f"Parameter {i} must be a non-empty string. "
                    f"Got: {type(arg).__name__} = {repr(arg)}"
                )

    def _initialize_tink(self, caas_kms_uri: str, keyset_data: str):
        """Initialize Google Tink encryption with envelope encryption pattern."""
        try:
            aead.register()

            self.KEYSET_ASSOCIATED_DATA = b"caas kek"
            self.CIPHERTEXT_ASSOCIATED_DATA = b"caas ums"

            # Extract and decode KEK
            kms_base64 = caas_kms_uri.split("caas-kms://")[-1]
            kms_key_bytes = base64.urlsafe_b64decode(
                self._add_base64_padding(kms_base64)
            )

            # Load KEK
            kek_handle = cleartext_keyset_handle.read(
                tink.BinaryKeysetReader(kms_key_bytes)
            )
            kek_aead = kek_handle.primitive(aead.Aead)

            # Decrypt DEK
            encrypted_keyset = base64.urlsafe_b64decode(
                self._add_base64_padding(keyset_data)
            )
            reader = tink.BinaryKeysetReader(encrypted_keyset)
            self.keyset_handle = tink.KeysetHandle.read_with_associated_data(
                reader, kek_aead, self.KEYSET_ASSOCIATED_DATA
            )

            # Create AEAD primitive for data decryption
            self.primitive = self.keyset_handle.primitive(aead.Aead)

            logger.info("Tink encryption initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Tink encryption: {e}")
            raise

    @staticmethod
    def _add_base64_padding(b64_str: str) -> str:
        """Add proper base64 padding to string."""
        return b64_str + "=" * (-len(b64_str) % 4)

    @staticmethod
    def _sanitize_column_name(col: str) -> str:
        """
        Sanitize column name to snake_case for consistent database schema.

        Transformations:
        - Spaces to underscores: "last login at" → "last_login_at"
        - Hyphens to underscores: "user-id" → "user_id"
        - Lowercase: "FirstName" → "firstname"
        - Remove special characters: "email!" → "email"
        - Multiple underscores to single: "first__name" → "first_name"

        Args:
            col: Original column name

        Returns:
            Sanitized column name (snake_case)
        """
        col = col.lower()
        col = col.replace(" ", "_").replace("-", "_")
        col = re.sub(r"[^a-z0-9_]", "", col)
        col = re.sub(r"_+", "_", col)
        col = col.strip("_")
        return col

    def _enhance_conn_str(self, conn_str: str) -> str:
        """Enhance database connection string with SSL and timeout settings."""
        db_ssl_mode = get_var("db_ssl_mode", "require")
        connect_timeout = get_var("db_connect_timeout", "30")

        params = {"sslmode": db_ssl_mode, "connect_timeout": connect_timeout}

        parsed = urlparse(conn_str)
        query_params = (
            dict(p.split("=") for p in parsed.query.split("&")) if parsed.query else {}
        )
        query_params.update(params)
        query = "&".join([f"{key}={value}" for key, value in query_params.items()])

        return parsed._replace(query=query).geturl()

    def _initialize_connection_pools(self):
        """Initialize thread-safe connection pools for source and target databases."""
        pool_min = int(get_var("db_pool_min_conn", 1))
        pool_max = int(get_var("db_pool_max_conn", 4))

        try:
            self.source_pool = pool.ThreadedConnectionPool(
                minconn=pool_min, maxconn=pool_max, dsn=self.source_conn_str
            )

            self.target_pool = pool.ThreadedConnectionPool(
                minconn=pool_min, maxconn=pool_max, dsn=self.target_conn_str
            )

            logger.info(
                f"Connection pools initialized (min={pool_min}, max={pool_max})"
            )

        except psycopg2.Error as e:
            logger.error(f"Failed to initialize connection pools: {e}")
            raise

    def _cleanup_pools(self):
        """Close all connection pools on shutdown."""
        try:
            if hasattr(self, "source_pool"):
                self.source_pool.closeall()
            if hasattr(self, "target_pool"):
                self.target_pool.closeall()
            logger.info("Connection pools closed successfully")
        except Exception as e:
            logger.error(f"Error closing connection pools: {e}")

    def _handle_shutdown(self, signum, frame):
        """Handle graceful shutdown on SIGTERM/SIGINT signals."""
        signal_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
        logger.warning(f"Shutdown signal received ({signal_name})")
        self._shutdown_requested = True

    @contextmanager
    def _get_source_conn(self):
        """Get connection from source pool with automatic return."""
        conn = None
        try:
            conn = self.source_pool.getconn()
            yield conn
        finally:
            if conn:
                self.source_pool.putconn(conn)

    @contextmanager
    def _get_target_conn(self):
        """Get connection from target pool with automatic return."""
        conn = None
        try:
            conn = self.target_pool.getconn()
            yield conn
        finally:
            if conn:
                self.target_pool.putconn(conn)

    @retry(
        stop=stop_after_attempt(MAX_RETRY_ATTEMPTS),
        wait=wait_exponential(multiplier=RETRY_WAIT_MULTIPLIER, min=4, max=10),
    )
    def execute_etl(
        self, table_name: str, last_updated_filter: Optional[datetime] = None
    ) -> Dict[str, Any]:


        table_config = TABLE_CONFIGS[table_name]
        has_watermark = table_config["watermark_column"] is not None
        has_encryption = len(table_config["encrypted_columns"]) > 0

        # Initialize run metadata
        run_meta = self._get_initial_run_meta(table_name, last_updated_filter)

        logger.info(
            f"ETL started for {table_name}",
            extra={
                "table_name": table_name,
                "incremental": last_updated_filter is not None,
                "encrypted_columns": len(table_config["encrypted_columns"]),
                "dlq_version": "json_payload",
            },
        )

        overall_start_time = time.time()
        total_rows_processed = 0
        total_rows_failed = 0
        current_high_watermark = last_updated_filter
        chunk_index = 0

        # Initialize memory tracking if available
        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            baseline_memory_mb = process.memory_info().rss / 1024 / 1024
            peak_memory_mb = baseline_memory_mb
            logger.info(f"Baseline memory: {baseline_memory_mb:.1f} MB")
        else:
            baseline_memory_mb = 0
            peak_memory_mb = 0

        try:
            df_iterator = self.extract_data_generator(table_name, last_updated_filter)

            for raw_df_chunk in df_iterator:
                if self._shutdown_requested:
                    logger.warning("Shutdown requested, stopping gracefully")
                    run_meta["status"] = "INTERRUPTED"
                    break

                chunk_index += 1
                chunk_start_time = time.time()

                # Enhanced chunk logging with progress tracking
                if chunk_index % 10 == 0 or chunk_index == 1:
                    log_extra = {
                        "table_name": table_name,
                        "chunk_index": chunk_index,
                        "chunk_size": len(raw_df_chunk),
                        "rows_processed_so_far": total_rows_processed,
                        "rows_failed_so_far": total_rows_failed,
                    }

                    # Add memory info if available
                    if PSUTIL_AVAILABLE:
                        current_memory_mb = process.memory_info().rss / 1024 / 1024
                        peak_memory_mb = max(peak_memory_mb, current_memory_mb)
                        log_extra["memory_mb"] = f"{current_memory_mb:.1f}"
                        log_extra[
                            "memory_delta_mb"
                        ] = f"{current_memory_mb - baseline_memory_mb:.1f}"

                    logger.info(
                        f"Processing chunk {chunk_index} for {table_name}",
                        extra=log_extra,
                    )

                # Update watermark
                if has_watermark:
                    watermark_col = table_config["watermark_column"]
                    if watermark_col in raw_df_chunk.columns and not raw_df_chunk.empty:
                        chunk_max = raw_df_chunk[watermark_col].max()
                        if pd.notna(chunk_max):
                            if hasattr(chunk_max, "to_pydatetime"):
                                chunk_max = chunk_max.to_pydatetime()
                            if (
                                current_high_watermark is None
                                or chunk_max > current_high_watermark
                            ):
                                current_high_watermark = chunk_max

                # Decrypt if needed
                decrypt_start = time.time()
                if has_encryption:
                    clean_chunk, failed_chunk = self.decrypt_data(
                        raw_df_chunk, table_name, table_config["encrypted_columns"]
                    )

                    # Route failures to JSON DLQ
                    if not failed_chunk.empty:
                        fail_count = len(failed_chunk)
                        total_rows_failed += fail_count
                        logger.warning(
                            f"Decryption failures in chunk {chunk_index}: {fail_count} rows",
                            extra={
                                "table_name": table_name,
                                "chunk_index": chunk_index,
                                "failed_rows": fail_count,
                                "failure_rate": f"{(fail_count / len(raw_df_chunk) * 100):.2f}%",
                            },
                        )
                        self._load_to_dlq_json(
                            failed_chunk, table_name, "decryption_failed"
                        )
                else:
                    clean_chunk = raw_df_chunk

                decrypt_time = time.time() - decrypt_start

                # Load clean data
                load_start = time.time()
                if not clean_chunk.empty:
                    self._load_with_fixed_chunks(clean_chunk, table_name, table_config)
                    total_rows_processed += len(clean_chunk)
                load_time = time.time() - load_start

                chunk_total_time = time.time() - chunk_start_time

                # Detailed chunk completion logging
                logger.info(
                    f"Chunk {chunk_index} completed for {table_name}",
                    extra={
                        "table_name": table_name,
                        "chunk_index": chunk_index,
                        "chunk_rows": len(raw_df_chunk),
                        "rows_written": (
                            len(clean_chunk) if not clean_chunk.empty else 0
                        ),
                        "rows_failed": (
                            len(failed_chunk)
                            if has_encryption and not failed_chunk.empty
                            else 0
                        ),
                        "decrypt_time_sec": f"{decrypt_time:.2f}",
                        "load_time_sec": f"{load_time:.2f}",
                        "chunk_total_time_sec": f"{chunk_total_time:.2f}",
                        "chunk_throughput_rows_per_sec": f"{len(raw_df_chunk) / max(chunk_total_time, 0.001):.0f}",
                        "cumulative_rows_processed": total_rows_processed,
                    },
                )

                # Save checkpoint
                if has_watermark:
                    self._save_checkpoint(
                        table_name, current_high_watermark, chunk_index
                    )

            # Finalize run metadata
            run_meta["rows_processed"] = total_rows_processed
            run_meta["rows_failed_decryption"] = total_rows_failed

            if run_meta["status"] != "INTERRUPTED":
                run_meta["status"] = "SUCCESS"

            run_meta["checksum"] = "N/A_STREAMING_MODE"

            # Calculate safe watermark with overlap
            if has_watermark and current_high_watermark:
                safe_watermark = current_high_watermark - timedelta(
                    minutes=WATERMARK_OVERLAP_MINUTES
                )
            else:
                safe_watermark = None

            run_meta["last_updated_filter"] = safe_watermark

            overall_duration = time.time() - overall_start_time

            # Calculate throughput
            overall_throughput = total_rows_processed / max(overall_duration, 0.001)

            logger.info(
                f"ETL completed for {table_name}",
                extra={
                    "table_name": table_name,
                    "status": run_meta["status"],
                    "duration_seconds": overall_duration,
                    "rows_processed": total_rows_processed,
                    "rows_failed": total_rows_failed,
                    "chunks_processed": chunk_index,
                    "overall_throughput_rows_per_sec": f"{overall_throughput:.0f}",
                    "avg_chunk_time_sec": f"{overall_duration / max(chunk_index, 1):.2f}",
                    "success_rate": f"{((total_rows_processed / max(total_rows_processed + total_rows_failed, 1)) * 100):.2f}%",
                    "peak_memory_mb": (
                        f"{peak_memory_mb:.1f}" if PSUTIL_AVAILABLE else "N/A"
                    ),
                },
            )

            # Print human-readable summary
            logger.info("=" * 80)
            logger.info(f"ETL SUMMARY: {table_name}")
            logger.info("=" * 80)
            logger.info(f"Status:{run_meta['status']}")
            logger.info(f"  Duration:           {overall_duration:.1f} seconds ({overall_duration / 60:.1f} minutes)")
            logger.info(f"  Chunks Processed:   {chunk_index}")
            logger.info(f"  Rows Processed:     {total_rows_processed:,}")
            logger.info(f"  Rows Failed:        {total_rows_failed:,}")
            logger.info(f"  Success Rate:       {((total_rows_processed / max(total_rows_processed + total_rows_failed, 1)) * 100):.2f}%")
            logger.info(f"  Throughput:         {overall_throughput:.0f} rows/sec")
            logger.info(f"  Avg Chunk Time:     {overall_duration / max(chunk_index, 1):.2f} seconds")
            
            if PSUTIL_AVAILABLE:
                logger.info(f"  Peak Memory:    {peak_memory_mb:.1f} MB")
                logger.info(f"  Memory Delta:  +{peak_memory_mb - baseline_memory_mb:.1f} MB")
            if has_watermark and safe_watermark:
                logger.info(f"  Watermark:      {safe_watermark.isoformat()}")
            logger.info("=" * 80)

        except Exception as e:
            error_context = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "chunks_processed": chunk_index,
                "rows_before_failure": total_rows_processed,
            }

            run_meta.update(
                {
                    "status": "FAILED",
                    "error_message": json.dumps(error_context),
                    "rows_processed": total_rows_processed,
                    "rows_failed_decryption": total_rows_failed,
                }
            )

            logger.error(
                f"ETL failed for {table_name}", extra=error_context, exc_info=True
            )
            raise

        finally:
            self._record_metadata(self._finalize_run(run_meta))

        return run_meta

    def extract_data_generator(self, table_name: str, last_updated_filter: Optional[datetime] = None) -> Iterator[pd.DataFrame]:
        """Extract data from source database using streaming generator."""
        table_config = TABLE_CONFIGS[table_name]
        columns = table_config["columns"]
        watermark_col = table_config["watermark_column"]

        column_list = sql.SQL(", ").join([sql.Identifier(col) for col in columns])
        query = sql.SQL("SELECT {columns} FROM {table}").format(
            columns=column_list, table=sql.Identifier(table_name)
        )

        if watermark_col and last_updated_filter:
            query = sql.SQL(
                "{base} WHERE {watermark_col} > %s ORDER BY {watermark_col}"
            ).format(base=query, watermark_col=sql.Identifier(watermark_col))
            params = (last_updated_filter,)
        else:
            if watermark_col:
                query = sql.SQL("{base} ORDER BY {watermark_col}").format(
                    base=query, watermark_col=sql.Identifier(watermark_col)
                )
            params = None

        with self._get_source_conn() as conn:
            query_str = query.as_string(conn)

            for chunk in pd.read_sql(
                query_str, conn, params=params, chunksize=self.read_chunk_size
            ):

                yield chunk

    def decrypt_data(self, df: pd.DataFrame, table_name: str, encrypted_columns: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
        # Fast path: no encryption, return original dataframe
        if not encrypted_columns:
            return df, pd.DataFrame()

        # Single copy for working data
        decrypted_df = df.copy()
        has_failures = pd.Series(False, index=df.index)

        for encrypted_col in encrypted_columns:
            ciphertext_values = df[encrypted_col].values
            decrypted_values = self._decrypt_column_batch(ciphertext_values)

            # Determine output column name
            if encrypted_col.startswith("e_"):
                decrypted_col = encrypted_col[2:]  # Remove 'e_' prefix
            else:
                decrypted_col = encrypted_col  # Keep same name

            decrypted_df[decrypted_col] = decrypted_values
            has_failures |= decrypted_values == DECRYPTION_FAILED_MARKER

        # Create failed dataframe
        if has_failures.any():
            failed_df = df[has_failures].copy()
        else:
            failed_df = pd.DataFrame()

        # Create clean dataframe
        clean_df = decrypted_df[~has_failures].copy()

        # *** FIX: Only drop columns with 'e_' prefix ***
        cols_to_drop = [col for col in encrypted_columns if col.startswith("e_")]
        if cols_to_drop:
            clean_df = clean_df.drop(columns=cols_to_drop, errors="ignore")

        logger.debug(
            f"Decryption complete for {table_name}: "
            f"{len(clean_df)} clean, {len(failed_df)} failed"
        )

        return clean_df, failed_df
   
    def _decrypt_column_batch(self, ciphertext_array: np.ndarray) -> np.ndarray:
        """
        Decrypt an entire column of ciphertext values.
        FIX: Returns raw JSON strings, DOES NOT parse into Dicts.
        """
        # Pre-allocate result array
        results = np.empty(len(ciphertext_array), dtype=object)

        # Process each value
        for i, ciphertext_b64 in enumerate(ciphertext_array):
            try:
                # Handle null/empty values
                if not ciphertext_b64 or pd.isna(ciphertext_b64):
                    results[i] = None
                    continue

                # Decode base64
                cipher = base64.urlsafe_b64decode(
                    self._add_base64_padding(ciphertext_b64)
                )

                # Decrypt using Tink primitive
                plain = self.primitive.decrypt(cipher, self.CIPHERTEXT_ASSOCIATED_DATA)

                # --- THE FIX IS HERE ---
                # OLD WAY: json.loads(plain.decode(...))  <-- This created the 'dict' error
                # NEW WAY: Just decode to string. Let Postgres handle the JSON.
                results[i] = plain.decode("utf-8")
                # -----------------------

            except Exception as e:
                # Only log first few failures to avoid log spam
                if i < 3:
                    logger.debug(f"Decryption failed for row {i} ({type(e).__name__})")
                results[i] = DECRYPTION_FAILED_MARKER

        return results
    
    def _vectorized_transform(self, df: pd.DataFrame, table_config: Dict[str, Any]):
        """
        OPTIMIZED: Vectorized transformations to replace row-by-row checks.
        Prepares data so _transactional_upsert can dump it blindly.
        """
        # 1. Handle JSON columns (Explicit Config)
        # This replaces the slow isinstance(val, dict) check
        for col in table_config.get("json_columns", []):
            # Check actual column name (handle e_ prefix logic if necessary, though here keys usually match)
            if col in df.columns:
                # Fast vectorized apply. 
                df[col] = df[col].apply(
                    lambda x: json.dumps(x, default=str) if isinstance(x, (dict, list)) else x
                )
        
        # 2. Handle Dates (Auto-detect)
        # Convert all datetime objects to ISO Strings at once
        time_cols = df.select_dtypes(include=['datetime', 'datetimetz']).columns
        for col in time_cols:
            df[col] = df[col].dt.strftime('%Y-%m-%d %H:%M:%S.%f%z')

        # 3. Handle NaNs (Bulk Replace)
        # Psycopg2 requires Python None, not Numpy NaN
        df.replace({np.nan: None}, inplace=True)

    def _load_with_fixed_chunks(self, df: pd.DataFrame, table_name: str, table_config: Dict[str, Any]):
        """Load data to target database in fixed-size chunks."""
        
        # --- FIX: Apply Vectorized Transform ONCE before chunking ---
        self._vectorized_transform(df, table_config)
        # ------------------------------------------------------------

        for i in range(0, len(df), self.fixed_chunk_size):
            chunk = df.iloc[i : i + self.fixed_chunk_size]
            self._transactional_upsert(chunk, table_name, table_config)
            
            
    def _transactional_upsert(self, df: pd.DataFrame, table_name: str, table_config: Dict[str, Any]):
        """Perform atomic upsert operation with proper transaction handling."""

        # Perform upsert (DML transaction)
        with self._get_target_conn() as conn:
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)

            try:
                with conn.cursor() as cur:
                    id_column = table_config["id_column"]
                    columns = [sql.Identifier(col) for col in df.columns]

                    updates = [
                        sql.SQL("{} = EXCLUDED.{}").format(
                            sql.Identifier(col), sql.Identifier(col)
                        )
                        for col in df.columns
                        if col != id_column
                    ]

                    data = list(df.itertuples(index=False, name=None))

                    # Calculate safe page size (prevent parameter overflow)
                    max_params = 32767
                    num_columns = len(df.columns)
                    safe_page_size = min(len(df), (max_params // num_columns) - 1)
                    
                    execute_values(
                        cur,
                        sql.SQL(
                            "INSERT INTO {} ({}) VALUES %s "
                            "ON CONFLICT ({}) DO UPDATE SET {}"
                        ).format(
                            sql.Identifier(table_name),
                            sql.SQL(", ").join(columns),
                            sql.Identifier(id_column),
                            (
                                sql.SQL(", ").join(updates)
                                if updates
                                else sql.SQL("{} = EXCLUDED.{}").format(
                                    sql.Identifier(id_column),
                                    sql.Identifier(id_column)
                                )
                            ),
                        ),
                        data,
                        page_size=safe_page_size,
                    )
                    conn.commit()

            except psycopg2.errors.DeadlockDetected:
                logger.warning(f"Deadlock detected for {table_name}, will retry")
                conn.rollback()
                raise

            except Exception as e:
                logger.error(f"Upsert error for {table_name}: {e}")
                conn.rollback()
                raise


    def _build_column_definitions(self, columns: List[str], schema_info: Dict[str, str], id_column: str) -> List[sql.SQL]:
        """Build column definitions for CREATE TABLE statement."""
        column_defs = []

        for col in columns:
            col_type = schema_info.get(col, "TEXT")
            mapped_type = PG_TYPE_MAP.get(col_type.lower(), "TEXT")

            if col == id_column:
                column_defs.append(
                    sql.SQL("{} {} PRIMARY KEY").format(
                        sql.Identifier(col), sql.SQL(mapped_type)
                    )
                )
            else:
                column_defs.append(
                    sql.SQL("{} {}").format(sql.Identifier(col), sql.SQL(mapped_type))
                )

        return column_defs

    # =====================================================================================
    # ============================ JSON PAYLOAD DLQ =======================================
    # =====================================================================================

    def _load_to_dlq_json(self, df: pd.DataFrame, source_table_name: str, reason: str):
        records = []

        # Get config for this table
        table_config = TABLE_CONFIGS.get(source_table_name, {})
        id_column = table_config.get("id_column", "id")
        encrypted_cols = table_config.get("encrypted_columns", [])

        for idx, row in df.iterrows():
            # Extract key identifiers (best effort)
            record_id = self._extract_identifier(
                row, id_column, idx, source_table_name
            )
            identity_id = self._extract_field(row, "identity_id")
            login_id = self._extract_field(row, "login_id")

            # Serialize entire row as JSON
            raw_data = self._serialize_row_to_json(row)

            # Build DLQ record
            records.append(
                {
                    "source_table": source_table_name,
                    "failed_at": datetime.now(timezone.utc),
                    "failure_reason": reason,
                    "record_id": record_id,
                    "identity_id": identity_id,
                    "login_id": login_id,
                    "raw_data": json.dumps(raw_data),
                    "column_count": len(row),
                    "encrypted_columns": [
                        col
                        for col in df.columns
                        if col in encrypted_cols
                        or col.startswith("e_")
                        or col in ["phone_detail", "email_detail", "address_detail"]
                    ],
                    "decryption_error": f"Failed to decrypt one or more fields. Reason: {reason}",
                }
            )

        logger.info(
            f"Loading {len(records)} rows to JSON DLQ",
            extra={
                "source_table": source_table_name,
                "failed_rows": len(records),
                "failure_reason": reason,
                "storage_format": "JSONB",
                "schema_agnostic": True,
            },
        )

        # Bulk insert to DLQ
        with self._get_target_conn() as conn:
            with conn.cursor() as cur:
                # Ensure DLQ table exists
                self._ensure_dlq_structure_json(conn)

                # Insert records
                execute_values(
                    cur,
                    """
                    INSERT INTO decryption_dlq_json (
                        source_table, failed_at, failure_reason, record_id,
                        identity_id, login_id, raw_data, column_count,
                        encrypted_columns, decryption_error
                    ) VALUES %s
                        ON CONFLICT (source_table, record_id, failed_at) 
                    DO NOTHING
                    """,
                    [
                        (
                            r["source_table"],
                            r["failed_at"],
                            r["failure_reason"],
                            r["record_id"],
                            r["identity_id"],
                            r["login_id"],
                            r["raw_data"],
                            r["column_count"],
                            r["encrypted_columns"],
                            r["decryption_error"],
                        )
                        for r in records
                    ],
                )
                conn.commit()

                logger.debug(f"JSON DLQ insert complete for {source_table_name}")

    def _extract_identifier(self, row: pd.Series, id_column: str, idx: int, table_name: str) -> str:
        """Extract record identifier from row (best effort)."""
        # Try configured id_column first
        if id_column in row and pd.notna(row[id_column]):
            return str(row[id_column])

        # Try common identifier columns
        for col in ["id", "identity_id", "user_id", "record_id"]:
            if col in row and pd.notna(row[col]):
                return str(row[col])

        # Fallback: generate unique identifier
        return f"unknown_{table_name}_{idx}_{int(datetime.now().timestamp())}"

    def _extract_field(self, row: pd.Series, field_name: str) -> Optional[str]:
        """Extract field value from row (returns None if missing/NA)."""
        if field_name in row and pd.notna(row[field_name]):
            return str(row[field_name])
        return None

    def _serialize_row_to_json(self, row: pd.Series) -> Dict[str, Any]:
        raw_data = {}

        for key, value in row.items():
            # Handle pandas NA
            if pd.isna(value):
                raw_data[key] = None
            # Handle timestamps
            elif isinstance(value, (pd.Timestamp, datetime)):
                raw_data[key] = (
                    value.isoformat() if hasattr(value, "isoformat") else str(value)
                )
            # Handle numpy types
            elif isinstance(value, (np.integer, np.floating)):
                raw_data[key] = value.item()
            # Handle already JSON-serializable types
            elif isinstance(value, (str, int, float, bool, dict, list, type(None))):
                raw_data[key] = value
            # Handle numpy arrays
            elif hasattr(value, "tolist"):
                raw_data[key] = value.tolist()
            # Fallback: convert to string
            else:
                raw_data[key] = str(value)

        return raw_data

    def _ensure_dlq_structure_json(self, conn):
        "Create schema-agnostic DLQ table using JSON payload storage."
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS decryption_dlq_json (
                    -- DLQ metadata (queryable, indexed)
                    dlq_id BIGSERIAL PRIMARY KEY,
                    source_table TEXT NOT NULL,
                    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    failure_reason TEXT NOT NULL,
                    retry_count INT DEFAULT 0,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolved_at TIMESTAMPTZ,
                    resolved_by TEXT,
                    resolution_notes TEXT,

                    -- Key identifiers (extracted for fast querying)
                    record_id TEXT,
                    identity_id TEXT,
                    login_id TEXT,

                    -- Raw payload (SCHEMA-AGNOSTIC)
                    raw_data JSONB NOT NULL,

                    -- Metadata about the failure
                    column_count INT,
                    encrypted_columns TEXT[],
                    decryption_error TEXT,

                    -- Audit fields
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW(),

                    -- Prevent exact duplicates
                    UNIQUE(source_table, record_id, failed_at)
                    );

                -- GIN index for fast JSONB queries
                CREATE INDEX IF NOT EXISTS idx_dlq_json_raw_data
                    ON decryption_dlq_json USING GIN (raw_data);

                -- B-tree indexes for common filters
                CREATE INDEX IF NOT EXISTS idx_dlq_json_unresolved
                    ON decryption_dlq_json(source_table, resolved, failed_at)
                    WHERE resolved = FALSE;

                CREATE INDEX IF NOT EXISTS idx_dlq_json_identity
                    ON decryption_dlq_json(identity_id)
                    WHERE identity_id IS NOT NULL;

                CREATE INDEX IF NOT EXISTS idx_dlq_json_record
                    ON decryption_dlq_json(source_table, record_id);

                CREATE INDEX IF NOT EXISTS idx_dlq_json_failed_at
                    ON decryption_dlq_json(failed_at DESC);

                -- Trigger to update updated_at timestamp
                CREATE OR REPLACE FUNCTION update_dlq_json_timestamp()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = NOW();
                RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;

                DROP TRIGGER IF EXISTS tr_dlq_json_updated ON decryption_dlq_json;
                CREATE TRIGGER tr_dlq_json_updated
                    BEFORE UPDATE ON decryption_dlq_json
                    FOR EACH ROW
                    EXECUTE FUNCTION update_dlq_json_timestamp();
                """
            )
            conn.commit()

            logger.debug("JSON DLQ schema ensured")

    # =====================================================================================
    # ============================ METADATA & CHECKPOINTS =================================
    # =====================================================================================

    def _save_checkpoint(self, table_name: str, watermark: Optional[datetime], chunk_index: int):
        """Save checkpoint after successful chunk processing."""
        if watermark is None:
            return

        with self._get_target_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO etl_checkpoints (
                        table_name, watermark, chunk_index, checkpoint_time
                    ) VALUES (%s, %s, %s, NOW())
                        ON CONFLICT (table_name)
                    DO UPDATE SET
                        watermark = EXCLUDED.watermark,
                        chunk_index = EXCLUDED.chunk_index,
                        checkpoint_time = EXCLUDED.checkpoint_time
                    """,
                    (table_name, watermark, chunk_index),
                )
                conn.commit()

    def _get_initial_run_meta(self, table_name: str, last_updated_filter: Optional[datetime]) -> Dict[str, Any]:
        """Initialize run metadata dictionary."""
        return {
            "table_name": table_name,
            "start_time": datetime.now(timezone.utc),
            "end_time": None,
            "rows_processed": 0,
            "rows_failed_decryption": 0,
            "status": "RUNNING",
            "checksum": None,
            "last_updated_filter": last_updated_filter,
            "error_message": None,
            "duration_seconds": None,
        }

    def _finalize_run(self, run_meta: Dict[str, Any]) -> Dict[str, Any]:
        """Finalize run metadata with end time and duration."""
        run_meta["end_time"] = datetime.now(timezone.utc)
        if run_meta["start_time"] and run_meta["end_time"]:
            duration = (run_meta["end_time"] - run_meta["start_time"]).total_seconds()
            run_meta["duration_seconds"] = duration
        return run_meta

    def _record_metadata(self, run_meta: Dict[str, Any]):
        """Record ETL run metadata for observability."""
        with self._get_target_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO etl_metadata (
                        table_name, run_start, run_end, rows_processed,
                        rows_failed_decryption, status, checksum,
                        last_updated_filter, error_message, duration_seconds
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        run_meta["table_name"],
                        run_meta["start_time"],
                        run_meta.get("end_time"),
                        run_meta.get("rows_processed", 0),
                        run_meta.get("rows_failed_decryption", 0),
                        run_meta["status"],
                        run_meta.get("checksum"),
                        run_meta.get("last_updated_filter"),
                        run_meta.get("error_message"),
                        run_meta.get("duration_seconds"),
                    ),
                )
                conn.commit()


# =====================================================================================
# ============================ AIRFLOW DAG ============================================
# =====================================================================================


def get_db_connection_string(conn_id: str) -> str:
    """Build PostgreSQL connection string from Airflow connection."""
    conn = BaseHook.get_connection(conn_id)
    return (
        f"postgresql://{conn.login}:{quote_plus(conn.password)}"
        f"@{conn.host}:{conn.port}/{conn.schema}"
    )


def _serialize_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize metadata for XCom storage."""
    serialized = meta.copy()
    for key, value in serialized.items():
        if isinstance(value, datetime):
            serialized[key] = value.isoformat()
    return serialized


@dag(
    dag_id="etl_tool",
    default_args={
        "owner": "karplexus",
        "depends_on_past": False,
        "email": get_var("etl_alert_email", "siddaling.b@karplexus.com"),
        "email_on_failure": True,
        "email_on_retry": False,
        "retries": 3,
        "execution_timeout": timedelta(
            minutes=int(get_var("etl_execution_timeout", 90))
        ),
    },
    schedule=get_var("tink_etl_schedule", "0 * * * *"),
    description="Multi-table ETL with JSON Payload DLQ",
    start_date=pendulum.datetime(2026, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
    tags=["etl", "tink", "encryption", "json_dlq", "v1.0.0"],
)
def tink_multi_table_etl_json_dlq():
    # Get tables to process
    tables_to_process = get_var(
        "etl_tables_to_process",
        default=[
            "identities",
            "credentials",
            "mapped_user_application",
            "identity_device_profile",
            "identity_contact_details",
        ],
        deserialize_json=True,
    )

    @task
    def initialize_etl_environment(**context):
        """Initialize ETL infrastructure (metadata tables, DLQ, checkpoints)."""
        target_conn_str = get_db_connection_string("target_db")

        with psycopg2.connect(target_conn_str) as conn:
            with conn.cursor() as cur:
                # Create metadata table
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS etl_metadata (
                    id BIGSERIAL PRIMARY KEY,
                    table_name TEXT NOT NULL,
                    run_start TIMESTAMPTZ NOT NULL,
                    run_end TIMESTAMPTZ,
                    rows_processed BIGINT,
                    rows_failed_decryption BIGINT,
                    status TEXT,
                    checksum TEXT,
                    last_updated_filter TIMESTAMPTZ,
                    error_message TEXT,
                    duration_seconds NUMERIC
                    );
                    CREATE INDEX IF NOT EXISTS idx_etl_metadata_table_status
                        ON etl_metadata(table_name, status, run_start DESC);
                    """
                )

                # Create checkpoint table
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS etl_checkpoints (
                    table_name TEXT PRIMARY KEY,
                    watermark TIMESTAMPTZ,
                    chunk_index INT,
                    checkpoint_time TIMESTAMPTZ
                    );
                    """
                )

                conn.commit()

        logger.info("ETL environment initialized")
        return True
    
    @task
    def validate_source_schemas():
        """
        Validate source DB schemas against TABLE_CONFIGS once per DAG run.
        """
        source_conn_str = get_db_connection_string("source_db")
    
        with psycopg2.connect(source_conn_str) as conn:
            for table_name, config in TABLE_CONFIGS.items():
                expected_cols = set(config["columns"])
    
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND table_name = %s
                        """,
                        (table_name,),
                    )
                    actual_cols = {row[0] for row in cur.fetchall()}
    
                missing = expected_cols - actual_cols
                if missing:
                    raise AirflowException(
                        f"Schema validation failed for {table_name}. "
                        f"Missing columns: {missing}"
                    )
    
                extra = actual_cols - expected_cols
                if extra:
                    logger.warning(
                        f"Schema drift detected for {table_name}: {extra}"
                    )
    
        logger.info("All source table schemas validated successfully")
        return True
    

    @task
    def ensure_target_tables():
        """
        Ensure all target DB tables exist with correct structure.
        Handles renaming 'e_' columns to match decrypted output.
        """
        source_conn_str = get_db_connection_string("source_db")
        target_conn_str = get_db_connection_string("target_db")

        with psycopg2.connect(source_conn_str) as source_conn, \
             psycopg2.connect(target_conn_str) as target_conn:

            for table_name, config in TABLE_CONFIGS.items():
                columns = config["columns"]
                id_column = config["id_column"]
                encrypted_cols = set(config.get("encrypted_columns", []))

                # Fetch source column types
                with source_conn.cursor() as src_cur:
                    placeholders = ",".join(["%s"] * len(columns))
                    src_cur.execute(
                        f"""
                        SELECT column_name, data_type
                        FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND table_name = %s
                          AND column_name IN ({placeholders})
                        ORDER BY ordinal_position
                        """,
                        [table_name] + columns,
                    )
                    # Map: e_legal_name -> text
                    schema_info = {row[0]: row[1] for row in src_cur.fetchall()}

                if not schema_info:
                    raise AirflowException(f"Source schema not found for {table_name}")

                # Ensure table in target
                with target_conn.cursor() as tgt_cur:
                    tgt_cur.execute("SELECT to_regclass(%s)", (table_name,))
                    exists = tgt_cur.fetchone()[0]

                    if not exists:
                        column_defs = []
                        for col in columns:
                            # --- FIX STARTS HERE ---
                            # 1. Determine the Target Name (Strip 'e_' if encrypted)
                            if col in encrypted_cols and col.startswith("e_"):
                                target_col_name = col[2:]  # e_legal_name -> legal_name
                            else:
                                target_col_name = col

                            # 2. Get Type using the SOURCE Name
                            src_type = schema_info.get(col, "TEXT")
                            mapped_type = PG_TYPE_MAP.get(src_type.lower(), "TEXT")

                            # 3. Build Definition using TARGET Name
                            # Using quotes "" protects against reserved keywords
                            if col == id_column:
                                column_defs.append(f'"{target_col_name}" {mapped_type} PRIMARY KEY')
                            else:
                                column_defs.append(f'"{target_col_name}" {mapped_type}')
                            # --- FIX ENDS HERE ---

                        create_sql = f"""
                            CREATE TABLE {table_name} (
                                {", ".join(column_defs)}
                            )
                        """
                        tgt_cur.execute(create_sql)
                        logger.info(f"Created target table {table_name}")
                    
                    else:
                        logger.info(f"Target table {table_name} already exists.")
                        # Optional: You could add logic here to ALTER table if columns are missing

            target_conn.commit()

        logger.info("All target tables ensured successfully")
        return True
    

    @task
    def process_single_table(table_name: str):
        """Process a single table through the complete ETL pipeline."""
        if table_name not in ALLOWED_TABLES:
            raise ValueError(f"Table '{table_name}' not allowed")

        read_chunk_size = int(get_var("etl_read_chunk_size", DEFAULT_READ_CHUNK_SIZE))
        write_chunk_size = int(get_var("etl_write_chunk_size", DEFAULT_WRITE_CHUNK_SIZE))

        config = {
            "caas_kms_uri": get_var("etl_caas_kms_uri"),
            "keyset_data": get_var("etl_keyset_data"),
            "source_conn_str": get_db_connection_string("source_db"),
            "target_conn_str": get_db_connection_string("target_db"),
            "chunk_size": write_chunk_size,
            "read_chunk_size": read_chunk_size,
        }

        if not config["caas_kms_uri"] or not config["keyset_data"]:
            raise AirflowException("Encryption variables not configured")

        etl_processor = TinkETL(**config)

        table_config = TABLE_CONFIGS[table_name]
        last_run = None

        if table_config["watermark_column"]:
            target_conn_str = config["target_conn_str"]
            with psycopg2.connect(target_conn_str) as target_conn:
                with target_conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT MAX(last_updated_filter)
                        FROM etl_metadata
                        WHERE table_name = %s
                          AND status = 'SUCCESS'
                        """,
                        (table_name,),
                    )
                    last_run = cur.fetchone()[0]

        logger.info(f"Processing {table_name} (last watermark: {last_run})")

        result = etl_processor.execute_etl(
            table_name=table_name, last_updated_filter=last_run
        )

        return _serialize_meta(result)

    @task(trigger_rule="all_done")
    def log_summary(**context):
        """Log summary of all ETL runs."""
        ti = context["task_instance"]
        task_ids = [f"process_{table}" for table in tables_to_process]
        xcom_results = ti.xcom_pull(task_ids=task_ids)

        logger.info("=" * 60)
        logger.info("ETL RUN SUMMARY")
        logger.info("=" * 60)

        total_processed = 0
        successful_tables = []
        failed_tables = []

        if xcom_results:
            for result in xcom_results:
                if not result:
                    continue

                if isinstance(result, dict):
                    result = [result]

                for res in result:
                    table = res.get("table_name", "unknown")
                    status = res.get("status", "UNKNOWN")
                    rows = res.get("rows_processed", 0)
                    duration = res.get("duration_seconds", 0)

                    if status == "SUCCESS":
                        successful_tables.append(table)
                        total_processed += rows
                        logger.info(f"✓ {table}: {rows:,} rows in {duration:.1f}s")
                    else:
                        failed_tables.append(table)
                        logger.error(f"✗ {table}: FAILED")

        logger.info("-" * 60)
        logger.info(f"Total: {total_processed:,} rows")
        logger.info(f"Success: {len(successful_tables)}")
        if failed_tables:
            logger.warning(f"Failed: {len(failed_tables)}")
        logger.info("=" * 60)

    # Task dependencies
    init_task = initialize_etl_environment()
    val_source = validate_source_schemas()  
    prep_target = ensure_target_tables()

    processing_tasks = []
    for table in tables_to_process:
        task_id = f"process_{table}"
        processing_task = process_single_table.override(task_id=task_id)(
            table_name=table
        )
        processing_tasks.append(processing_task)

    summary_task = log_summary()

    # Sequential execution (recommended)
    init_task >> val_source >> prep_target 
    
    previous_task = prep_target
    for t in processing_tasks:
        previous_task >> t
        previous_task = t
    previous_task >> summary_task


# Instantiate the DAG
dag_instance = tink_multi_table_etl_json_dlq()
