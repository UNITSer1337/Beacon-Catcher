-- Rohpakete (Stufe 1)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ble_packets (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identifikation
    mac                 TEXT,           
    mac_address_type    TEXT,           -- 'public' / 'rpa' / 'nrpa' / 'static_random' / 'unknown'
    is_random_mac       INTEGER DEFAULT 0,
.
    -- Werte: 0,1,2,3 entsprechend Top-2-Bits des ersten Oktetts.
    mac_top_two_bits    INTEGER,

    -- Empfangs-Metadaten
    rssi                INTEGER,
    timestamp           TEXT NOT NULL,

    -- Hardware-stabile Fingerprint-Felder
    manufacturer_id     INTEGER,
    manufacturer_data   TEXT,
    service_uuids       TEXT,
    service_data        TEXT,
    service_data_keys   TEXT,
    tx_power            INTEGER,
    appearance          INTEGER,
    ad_types            TEXT,
    ad_payload_length   INTEGER,

    -- Variabel
    local_name          TEXT,

    -- Roh/Debug
    platform_data       TEXT
);
CREATE INDEX IF NOT EXISTS idx_ble_packets_mac
    ON ble_packets(mac);
CREATE INDEX IF NOT EXISTS idx_ble_packets_ts
    ON ble_packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_ble_packets_mfr
    ON ble_packets(manufacturer_id);
CREATE INDEX IF NOT EXISTS idx_ble_packets_addr_type
    ON ble_packets(mac_address_type);


-- Bursts (Stufe 2)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ble_bursts (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    
    mac                      TEXT NOT NULL,
    mac_address_type         TEXT,
    is_random_mac            INTEGER,
    mac_top_two_bits         INTEGER,

    started_at               TEXT NOT NULL,
    ended_at                 TEXT NOT NULL,
    duration_seconds         REAL,
    packet_count             INTEGER,

    rssi_min                 INTEGER,
    rssi_max                 INTEGER,
    rssi_avg                 REAL,
    rssi_stddev              REAL,

    primary_manufacturer_id  INTEGER,
    manufacturer_ids         TEXT,
    manufacturer_subtypes    TEXT,

    service_uuids_set        TEXT,
    service_data_keys_set    TEXT,
    ad_types_set             TEXT,

    tx_power_modal           INTEGER,
    tx_power_consistent      INTEGER,
    appearance               INTEGER,
    local_name               TEXT,
    ad_payload_length_avg    REAL,
    ad_payload_length_stddev REAL,

    cluster_id_3a            INTEGER,
    track_id_3c              INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ble_bursts_mac
    ON ble_bursts(mac);
CREATE INDEX IF NOT EXISTS idx_ble_bursts_started
    ON ble_bursts(started_at);
CREATE INDEX IF NOT EXISTS idx_ble_bursts_mfr
    ON ble_bursts(primary_manufacturer_id);
CREATE INDEX IF NOT EXISTS idx_ble_bursts_addr_type
    ON ble_bursts(mac_address_type);
CREATE INDEX IF NOT EXISTS idx_ble_bursts_cluster_3a
    ON ble_bursts(cluster_id_3a);
CREATE INDEX IF NOT EXISTS idx_ble_bursts_track_3c
    ON ble_bursts(track_id_3c);


-- Cluster (Stufe 3a)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ble_clusters_3a (
    cluster_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_hash        TEXT UNIQUE NOT NULL,
    fingerprint_components  TEXT,
    primary_manufacturer_id INTEGER,
    n_bursts                INTEGER,
    n_unique_macs           INTEGER,
    n_unique_addr_types     INTEGER,
    address_types           TEXT,
    n_low_quality           INTEGER,
    first_seen              TEXT,
    last_seen               TEXT,
    rssi_min                INTEGER,
    rssi_max                INTEGER,
    rssi_avg                REAL,
    total_packets           INTEGER
);


-- Tracks (Stufe 3c)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ble_tracks_3c (
    track_id                INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id_3a           INTEGER,
    n_bursts                INTEGER,
    n_unique_macs           INTEGER,
    macs                    TEXT,
    first_seen              TEXT,
    last_seen               TEXT,
    span_seconds            REAL,
    total_active_seconds    REAL,
    rssi_min                INTEGER,
    rssi_max                INTEGER,
    rssi_avg                REAL,
    rssi_stddev             REAL,
    total_packets           INTEGER,
    primary_manufacturer_id INTEGER,
    confidence_score        REAL,
    confidence_notes        TEXT
);
CREATE INDEX IF NOT EXISTS idx_tracks_cluster
    ON ble_tracks_3c(cluster_id_3a);


-- BLE Visits (Stufe 4)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ble_visits (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id            INTEGER NOT NULL
                          REFERENCES ble_tracks_3c(track_id)
                          ON DELETE CASCADE,
    started_at            TEXT NOT NULL,
    ended_at              TEXT NOT NULL,
    duration_seconds      REAL NOT NULL,
    gap_to_prev_seconds   REAL,
    burst_count           INTEGER NOT NULL,
    packet_count          INTEGER NOT NULL,
    rssi_min              INTEGER,
    rssi_max              INTEGER,
    rssi_avg              REAL,
    first_burst_id        INTEGER REFERENCES ble_bursts(id) ON DELETE SET NULL,
    last_burst_id         INTEGER REFERENCES ble_bursts(id) ON DELETE SET NULL,
    created_at            TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ble_visits_cluster ON ble_visits(cluster_id);
CREATE INDEX IF NOT EXISTS idx_ble_visits_started ON ble_visits(started_at);
CREATE INDEX IF NOT EXISTS idx_ble_visits_ended   ON ble_visits(ended_at);


-- Run-Tracking für Stufe 4
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS visit_runs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at            TEXT NOT NULL,
    ended_at              TEXT,
    mode                  TEXT NOT NULL,
    visit_gap_minutes     REAL NOT NULL,
    bursts_processed      INTEGER DEFAULT 0,
    visits_created        INTEGER DEFAULT 0,
    notes                 TEXT
);
CREATE INDEX IF NOT EXISTS idx_visit_runs_mode    ON visit_runs(mode);
CREATE INDEX IF NOT EXISTS idx_visit_runs_started ON visit_runs(started_at);