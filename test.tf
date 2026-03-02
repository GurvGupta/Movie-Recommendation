###############################################################################
# Google BigQuery Security Controls Test Module
#
# Production-ready test module for validating BigQuery security policies:
#   - KMS CMK encryption enforcement
#   - Dataset IAM configuration
#   - Table-level encryption setup
#   - Access controls and best practices
#
# Policies Tested:
#   GCP-SEC-001: BigQuery dataset must not be publicly accessible
#   GCP-SEC-BQ-KMS: BigQuery datasets must use customer-managed encryption keys
#   GCP-SEC-BQ-IAM: Dataset access must follow principle of least privilege
#   GCP-SEC-BQ-TABLE-ENC: BigQuery tables must have encryption configured
#
# Author: Security Team
# Version: 1.0.0
###############################################################################

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

data "google_client_config" "current" {}
data "google_project" "project" {
  project_id = var.project_id
}

###############################################################################
# KMS SETUP - Customer-Managed Encryption Keys (CMK)
###############################################################################

# KMS Key Ring
resource "google_kms_key_ring" "bigquery_keyring" {
  name     = var.kms_keyring_name
  location = var.region
  provider = google

  depends_on = [data.google_project.project]
}

# KMS Crypto Key for BigQuery datasets
resource "google_kms_crypto_key" "bigquery_key" {
  name                       = var.kms_crypto_key_name
  key_ring                   = google_kms_key_ring.bigquery_keyring.id
  rotation_period            = var.key_rotation_period # 90 days
  version_template {
    algorithm       = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    environment = var.environment
    purpose     = "bigquery-encryption"
  }
}

# KMS Crypto Key for BigQuery tables
resource "google_kms_crypto_key" "bigquery_table_key" {
  name                       = "${var.kms_crypto_key_name}-table"
  key_ring                   = google_kms_key_ring.bigquery_keyring.id
  rotation_period            = var.key_rotation_period
  version_template {
    algorithm       = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    environment = var.environment
    purpose     = "bigquery-table-encryption"
  }
}

# Grant BigQuery service account permission to use the key
resource "google_kms_crypto_key_iam_member" "bigquery_kms_access" {
  crypto_key_id = google_kms_crypto_key.bigquery_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:bq-${data.google_project.project.number}@bigquery-encryption.iam.gserviceaccount.com"
}

resource "google_kms_crypto_key_iam_member" "bigquery_table_kms_access" {
  crypto_key_id = google_kms_crypto_key.bigquery_table_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:bq-${data.google_project.project.number}@bigquery-encryption.iam.gserviceaccount.com"
}

###############################################################################
# COMPLIANT DATASETS - Security Best Practices
###############################################################################

# 1. SECURE: Private dataset with KMS CMK encryption and owner access only
resource "google_bigquery_dataset" "compliant_private_encrypted" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_private_encrypted" : "compliant_private_encrypted"
  friendly_name        = "Compliant: Private with KMS CMK"
  description          = "COMPLIANT: Private dataset with customer-managed encryption keys, owner access only"
  location             = var.region
  delete_contents_on_destroy = false
  default_table_expiration_ms = null

  # KMS CMK Encryption Configuration
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bigquery_key.id
  }

  # IAM-based access control - owner only
  access {
    role          = "OWNER"
    user_by_email = var.owner_email
  }

  labels = {
    compliance_level = "compliant"
    encryption       = "kms-cmk"
    pii_data         = "false"
    environment      = var.environment
  }
}

# 2. SECURE: Dataset with restricted group and user access
resource "google_bigquery_dataset" "compliant_restricted_access" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_restricted_access" : "compliant_restricted_access"
  friendly_name        = "Compliant: Restricted Access"
  description          = "COMPLIANT: Dataset with least privilege access (specific users/groups/service accounts)"
  location             = var.region
  delete_contents_on_destroy = false

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bigquery_key.id
  }

  # Owner access
  access {
    role          = "OWNER"
    user_by_email = var.owner_email
  }

  # Read-only access for analysts
  access {
    role           = "READER"
    group_by_email = var.reader_group_email
  }

  # Write access for data engineers
  access {
    role           = "EDITOR"
    group_by_email = var.editor_group_email
  }

  # Service account access for automated processes
  access {
    role          = "READER"
    user_by_email = var.service_account_email
  }

  labels = {
    compliance_level = "compliant"
    encryption       = "kms-cmk"
    pii_data         = "true"
    environment      = var.environment
  }
}

# 3. SECURE: Dataset with domain-restricted access (enterprise)
resource "google_bigquery_dataset" "compliant_domain_restricted" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_domain_restricted" : "compliant_domain_restricted"
  friendly_name        = "Compliant: Domain Restricted"
  description          = "COMPLIANT: Access limited to specific corporate domain"
  location             = var.region
  delete_contents_on_destroy = false

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bigquery_key.id
  }

  access {
    role          = "OWNER"
    user_by_email = var.owner_email
  }

  # Domain-level access
  access {
    role   = "READER"
    domain = var.corporate_domain
  }

  labels = {
    compliance_level = "compliant"
    encryption       = "kms-cmk"
    access_type      = "domain-restricted"
    environment      = var.environment
  }
}

# 4. SECURE: Audit dataset with strict access
resource "google_bigquery_dataset" "compliant_audit_logs" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_audit_logs" : "compliant_audit_logs"
  friendly_name        = "Compliant: Audit Logs"
  description          = "COMPLIANT: Immutable audit logs with KMS encryption and restricted access"
  location             = var.region
  delete_contents_on_destroy = false

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bigquery_key.id
  }

  access {
    role          = "OWNER"
    user_by_email = var.audit_service_account_email
  }

  access {
    role          = "READER"
    user_by_email = var.security_officer_email
  }

  labels = {
    compliance_level = "compliant"
    encryption       = "kms-cmk"
    audit_data       = "true"
    immutable        = "true"
    environment      = var.environment
  }
}

###############################################################################
# COMPLIANT TABLES WITH ENCRYPTION
###############################################################################

# 1. COMPLIANT: Table with column-level security and KMS encryption
resource "google_bigquery_table" "compliant_encrypted_table" {
  dataset_id          = google_bigquery_dataset.compliant_private_encrypted.dataset_id
  table_id            = var.dataset_prefix != "" ? "${var.dataset_prefix}_customer_pii" : "compliant_customer_pii"
  deletion_protection = true

  description = "COMPLIANT: Customer PII table with KMS encryption and column-level security"

  # KMS encryption at table level
  encryption_configuration {
    kms_key_name = google_kms_crypto_key.bigquery_table_key.id
  }

  schema = jsonencode([
    {
      name        = "customer_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Unique customer identifier"
    },
    {
      name        = "email"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Customer email (PII)"
      policy_tags = {
        names = [google_data_catalog_taxonomy_iam_binding.pii_taxonomy_iam.taxonomy]
      }
    },
    {
      name        = "phone"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Customer phone number (PII)"
      policy_tags = {
        names = [google_data_catalog_taxonomy_iam_binding.pii_taxonomy_iam.taxonomy]
      }
    },
    {
      name        = "created_date"
      type        = "DATE"
      mode        = "REQUIRED"
      description = "Record creation date"
    }
  ])

  labels = {
    encryption       = "kms-cmk"
    pii_data         = "true"
    environment      = var.environment
  }
}

# 2. COMPLIANT: Partitioned table with time-based security
resource "google_bigquery_table" "compliant_partitioned_table" {
  dataset_id          = google_bigquery_dataset.compliant_restricted_access.dataset_id
  table_id            = var.dataset_prefix != "" ? "${var.dataset_prefix}_events" : "compliant_events"
  deletion_protection = true

  description = "COMPLIANT: Event logs with partitioning and KMS encryption"

  encryption_configuration {
    kms_key_name = google_kms_crypto_key.bigquery_table_key.id
  }

  time_partitioning {
    type          = "DAY"
    field         = "event_timestamp"
    expiration_ms = 86400000 # 91 days
  }

  clustering = ["event_type", "user_id"]

  schema = jsonencode([
    {
      name        = "event_timestamp"
      type        = "TIMESTAMP"
      mode        = "REQUIRED"
      description = "Event timestamp for partitioning"
    },
    {
      name        = "event_type"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "Type of event for clustering"
    },
    {
      name        = "user_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "User identifier for clustering"
    },
    {
      name        = "event_data"
      type        = "JSON"
      mode        = "NULLABLE"
      description = "Event payload in JSON format"
    }
  ])

  labels = {
    encryption  = "kms-cmk"
    partitioned = "true"
    environment = var.environment
  }
}

###############################################################################
# NON-COMPLIANT DATASETS - Security Anti-Patterns
###############################################################################

# 1. NON-COMPLIANT: Public dataset with allUsers access
resource "google_bigquery_dataset" "non_compliant_public_all_users" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_public_all_users" : "non_compliant_public_all_users"
  friendly_name        = "Non-Compliant: Public (allUsers)"
  description          = "NON-COMPLIANT: Publicly accessible dataset - SECURITY VIOLATION"
  location             = var.region
  delete_contents_on_destroy = true

  # Public access - VIOLATION!
  access {
    role        = "READER"
    special_group = "projectReaders"
  }

  # Additional public access
  access {
    role        = "READER"
    special_group = "allUsers"
  }

  labels = {
    compliance_level = "non-compliant"
    violation_type   = "public-all-users"
    environment      = var.environment
  }
}

# 2. NON-COMPLIANT: Dataset with allAuthenticatedUsers access
resource "google_bigquery_dataset" "non_compliant_all_authenticated_users" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_all_authenticated" : "non_compliant_all_authenticated"
  friendly_name        = "Non-Compliant: All Authenticated Users"
  description          = "NON-COMPLIANT: Accessible by any Google Cloud authenticated user - SECURITY VIOLATION"
  location             = var.region
  delete_contents_on_destroy = true

  # Overly broad access - VIOLATION!
  access {
    role        = "EDITOR"
    special_group = "projectEditors"
  }

  access {
    role        = "READER"
    special_group = "allAuthenticatedUsers"
  }

  labels = {
    compliance_level = "non-compliant"
    violation_type   = "all-authenticated-users"
    environment      = var.environment
  }
}

# 3. NON-COMPLIANT: Dataset without KMS encryption (using Google-managed keys)
resource "google_bigquery_dataset" "non_compliant_no_kms" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_no_kms" : "non_compliant_no_kms"
  friendly_name        = "Non-Compliant: No KMS Encryption"
  description          = "NON-COMPLIANT: Using Google-managed keys instead of CMK - SECURITY VIOLATION"
  location             = var.region
  delete_contents_on_destroy = true

  # No encryption_configuration specified = uses Google-managed keys - VIOLATION!

  access {
    role          = "OWNER"
    user_by_email = var.owner_email
  }

  labels = {
    compliance_level = "non-compliant"
    violation_type   = "no-kms-encryption"
    encryption       = "google-managed"
    environment      = var.environment
  }
}

# 4. NON-COMPLIANT: Dataset with overly permissive group access
resource "google_bigquery_dataset" "non_compliant_broad_group_access" {
  dataset_id           = var.dataset_prefix != "" ? "${var.dataset_prefix}_broad_group" : "non_compliant_broad_group"
  friendly_name        = "Non-Compliant: Broad Group Access"
  description          = "NON-COMPLIANT: Everyone in org can write - SECURITY VIOLATION"
  location             = var.region
  delete_contents_on_destroy = true

  # Overly broad group access - VIOLATION!
  access {
    role           = "EDITOR"
    group_by_email = "everyone@example.com"
  }

  labels = {
    compliance_level = "non-compliant"
    violation_type   = "overly-permissive-group"
    environment      = var.environment
  }
}

# 5. NON-COMPLIANT: Table without encryption configuration
resource "google_bigquery_table" "non_compliant_unencrypted_table" {
  dataset_id          = google_bigquery_dataset.non_compliant_no_kms.dataset_id
  table_id            = var.dataset_prefix != "" ? "${var.dataset_prefix}_sensitive_data" : "non_compliant_sensitive_data"
  deletion_protection = false

  description = "NON-COMPLIANT: Sensitive data without KMS encryption - SECURITY VIOLATION"

  # No encryption_configuration = VIOLATION!

  schema = jsonencode([
    {
      name        = "user_id"
      type        = "STRING"
      mode        = "REQUIRED"
      description = "User ID"
    },
    {
      name        = "ssn"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Social Security Number (PII) - UNENCRYPTED - VIOLATION!"
    },
    {
      name        = "credit_card"
      type        = "STRING"
      mode        = "NULLABLE"
      description = "Credit card number (PCI) - UNENCRYPTED - VIOLATION!"
    }
  ])

  labels = {
    encryption       = "none"
    pii_data         = "true"
    environment      = var.environment
  }
}

###############################################################################
# DATA CATALOG - POLICY TAGS FOR COLUMN-LEVEL SECURITY
###############################################################################

# Create taxonomy for PII data
resource "google_data_catalog_taxonomy" "pii_taxonomy" {
  provider    = google
  display_name = var.dataset_prefix != "" ? "${var.dataset_prefix}_pii_taxonomy" : "pii_taxonomy"
  description = "Taxonomy for PII data classification"
  region      = var.region

  activated_policy_types = ["FINE_GRAINED_ACCESS_CONTROL"]
}

# Create policy tag for PII
resource "google_data_catalog_policy_tag" "pii_tag" {
  provider   = google
  taxonomy   = google_data_catalog_taxonomy.pii_taxonomy.id
  display_name = "PII Data"
  description = "Personally Identifiable Information"
}

# IAM binding for PII taxonomy (restrict access to sensitive columns)
resource "google_data_catalog_taxonomy_iam_binding" "pii_taxonomy_iam" {
  provider = google
  taxonomy = google_data_catalog_taxonomy.pii_taxonomy.id
  role     = "roles/datacatalog.tagTemplateUser"
  members = [
    "group:${var.security_team_group}",
    "serviceAccount:${var.service_account_email}"
  ]
}

###############################################################################
# ADDITIONAL SECURITY CONFIGURATIONS
###############################################################################

# Enable VPC Service Controls (optional) - requires VPC SC perimeter setup
# This is commented out as it requires pre-existing VPC SC infrastructure
/*
resource "google_access_context_manager_service_perimeter" "bigquery_perimeter" {
  parent       = "accessPolicies/${var.access_policy_id}"
  name         = "accessPolicies/${var.access_policy_id}/servicePerimeters/${var.dataset_prefix}_bigquery"
  title        = "BigQuery Service Perimeter"
  description  = "Service perimeter for BigQuery security"
  perimeterType = "PERIMETER_TYPE_REGULAR"

  status {
    resources = [
      "projects/${data.google_project.project.number}"
    ]
    restricted_services = [
      "bigquery.googleapis.com"
    ]
  }

  depends_on = [
    google_bigquery_dataset.compliant_private_encrypted,
    google_kms_crypto_key.bigquery_key
  ]
}
*/
