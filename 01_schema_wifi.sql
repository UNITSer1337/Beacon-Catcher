-- Hop-Sessions: dokumentiert in welchem Kanal/Zyklus der Scanner war
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hop_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id    INTEGER NOT NULL,
    hop_index   INTEGER NOT NULL,
    channel     INTEGER NOT NULL,
    dwell_ms    INTEGER NOT NULL,
    started_at  TEXT    NOT NULL,
    ended_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_hop_sessions_started ON hop_sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_hop_sessions_channel ON hop_sessions(channel);


-- Rohpakete (Stufe 1)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wifi_packets (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    mac                 TEXT    NOT NULL,
    timestamp           TEXT    NOT NULL,
    rssi                INTEGER,
    channel             INTEGER,

    ssid                TEXT,
    is_broadcast        INTEGER DEFAULT 0,
    is_random_mac       INTEGER DEFAULT 0,
    seq_num             INTEGER,
    retry_flag          INTEGER DEFAULT 0,

    ie_fingerprint      TEXT,
    tagged_params_hash  TEXT,
    ht_capabilities     TEXT,
    ext_capabilities    TEXT,
    vht_capabilities    TEXT,
    he_capabilities     TEXT,
    supported_rates     TEXT,
    vendor_ouis         TEXT,
    vendor_oui_set      TEXT,

    -- Verknüpfung zur Scanner-Session
    hop_session_id      INTEGER REFERENCES hop_sessions(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_wifi_packets_mac
    ON wifi_packets(mac);
CREATE INDEX IF NOT EXISTS idx_wifi_packets_ts
    ON wifi_packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_wifi_packets_mac_ts
    ON wifi_packets(mac, timestamp);
CREATE INDEX IF NOT EXISTS idx_wifi_packets_fingerprint
    ON wifi_packets(ie_fingerprint);
CREATE INDEX IF NOT EXISTS idx_wifi_packets_hop_session
    ON wifi_packets(hop_session_id);


-- Bursts (Stufe 2)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bursts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    mac                 TEXT    NOT NULL,
    is_random_mac       INTEGER DEFAULT 0,

    started_at          TEXT    NOT NULL,
    ended_at            TEXT    NOT NULL,
    duration_ms         INTEGER NOT NULL,
    packet_count        INTEGER NOT NULL,

    seq_num_first       INTEGER,
    seq_num_last        INTEGER,
    seq_num_min         INTEGER,
    seq_num_max         INTEGER,

    rssi_min            INTEGER,
    rssi_max            INTEGER,
    rssi_avg            REAL,

    channels_seen       TEXT,

    -- Inhalt
    ssids_probed        TEXT,
    has_broadcast       INTEGER DEFAULT 0,
    retry_count         INTEGER DEFAULT 0,

    ie_fingerprint      TEXT NOT NULL,
    tagged_params_hash  TEXT,
    ht_capabilities     TEXT,
    ext_capabilities    TEXT,
    vht_capabilities    TEXT,
    he_capabilities     TEXT,
    supported_rates     TEXT,
    vendor_ouis         TEXT,
    vendor_oui_set      TEXT,

    first_packet_id     INTEGER REFERENCES wifi_packets(id) ON DELETE SET NULL,
    last_packet_id      INTEGER REFERENCES wifi_packets(id) ON DELETE SET NULL,

    -- Cluster-Zuordnungen (Stufen 3a, 3b, 3c)
    cluster_id          INTEGER,
    cluster_id_hardcut  INTEGER,
    cluster_id_scored   INTEGER,

    created_at          TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_bursts_mac
    ON bursts(mac);
CREATE INDEX IF NOT EXISTS idx_bursts_started
    ON bursts(started_at);
CREATE INDEX IF NOT EXISTS idx_bursts_fingerprint
    ON bursts(ie_fingerprint);
CREATE INDEX IF NOT EXISTS idx_bursts_mac_started
    ON bursts(mac, started_at);
CREATE INDEX IF NOT EXISTS idx_bursts_cluster
    ON bursts(cluster_id);
CREATE INDEX IF NOT EXISTS idx_bursts_cluster_hardcut
    ON bursts(cluster_id_hardcut);
CREATE INDEX IF NOT EXISTS idx_bursts_cluster_scored
    ON bursts(cluster_id_scored);


-- Device-Cluster (Stufe 3)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_clusters (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,

    ie_fingerprint      TEXT NOT NULL,
    vendor_oui_set      TEXT,

    burst_count         INTEGER DEFAULT 0,
    mac_count           INTEGER DEFAULT 0,
    packet_count        INTEGER DEFAULT 0,
    random_mac_count    INTEGER DEFAULT 0,
    real_mac_count      INTEGER DEFAULT 0,

    first_seen          TEXT,
    last_seen           TEXT,
    duration_seconds    REAL,

    rssi_min            INTEGER,
    rssi_max            INTEGER,
    rssi_avg            REAL,

    -- Methode der Cluster-Bildung
    -- 'fingerprint_bucket'  (3a)
    -- 'fingerprint_hardcut' (3b)
    -- 'fingerprint_scored'  (3c)
    method              TEXT NOT NULL DEFAULT 'fingerprint_bucket',

    confidence_score    REAL,
    created_at          TEXT DEFAULT CURRENT_TIMESTAMP,
    notes               TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_clusters_fp
    ON device_clusters(ie_fingerprint);
CREATE INDEX IF NOT EXISTS idx_device_clusters_method
    ON device_clusters(method);
CREATE INDEX IF NOT EXISTS idx_device_clusters_first
    ON device_clusters(first_seen);


-- Run-Tracking
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS aggregation_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at          TEXT NOT NULL,
    ended_at            TEXT,
    burst_timeout_ms    INTEGER NOT NULL,
    packets_processed   INTEGER DEFAULT 0,
    bursts_created      INTEGER DEFAULT 0,
    range_from          TEXT,
    range_to            TEXT,
    notes               TEXT
);

CREATE TABLE IF NOT EXISTS clustering_runs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at          TEXT NOT NULL,
    ended_at            TEXT,
    method              TEXT NOT NULL,
    bursts_processed    INTEGER DEFAULT 0,
    clusters_created    INTEGER DEFAULT 0,
    notes               TEXT
);

-- WiFi Visits (Stufe 4)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wifi_visits (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    cluster_id            INTEGER NOT NULL
                          REFERENCES device_clusters(id)
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
    first_burst_id        INTEGER REFERENCES bursts(id) ON DELETE SET NULL,
    last_burst_id         INTEGER REFERENCES bursts(id) ON DELETE SET NULL,
    created_at            TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_wifi_visits_cluster ON wifi_visits(cluster_id);
CREATE INDEX IF NOT EXISTS idx_wifi_visits_started ON wifi_visits(started_at);
CREATE INDEX IF NOT EXISTS idx_wifi_visits_ended   ON wifi_visits(ended_at);