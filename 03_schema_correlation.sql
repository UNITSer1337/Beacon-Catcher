-- Korrelation
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS device_correlations (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identitäten (WiFi-Cluster und BLE-Track die korrelieren)
    wifi_cluster_id          INTEGER NOT NULL
                             REFERENCES device_clusters(id)
                             ON DELETE CASCADE,
    ble_track_id             INTEGER NOT NULL
                             REFERENCES ble_tracks_3c(track_id)
                             ON DELETE CASCADE,

    -- Konfidenz und Begründung
    confidence_score         REAL NOT NULL,        -- 0..1
    confidence_notes         TEXT,

    -- Korrelations-Statistik
    n_overlapping_visit_pairs INTEGER NOT NULL,    -- wie viele Visit-Paare überlappen
    total_overlap_seconds    REAL NOT NULL,        -- Summe der zeitlichen Überlappung
    avg_overlap_ratio        REAL,                 -- 0..1, mittlere Überlappung pro Paar

    -- RSSI-Konsistenz
    wifi_rssi_distance_class TEXT,                 -- 'near' / 'medium' / 'far'
    ble_rssi_distance_class  TEXT,
    rssi_classes_match       INTEGER,              -- 1 wenn beide gleich, 0 sonst

    -- Zeitliche Spanne der Korrelation
    first_overlap_at         TEXT NOT NULL,
    last_overlap_at          TEXT NOT NULL,

    -- Meta
    created_at               TEXT DEFAULT CURRENT_TIMESTAMP,

    -- Eine WiFi-Cluster -> BLE-Track-Beziehung nur einmal
    UNIQUE(wifi_cluster_id, ble_track_id)
);

CREATE INDEX IF NOT EXISTS idx_corr_wifi
    ON device_correlations(wifi_cluster_id);
CREATE INDEX IF NOT EXISTS idx_corr_ble
    ON device_correlations(ble_track_id);
CREATE INDEX IF NOT EXISTS idx_corr_confidence
    ON device_correlations(confidence_score);


-- Run-Tracking
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS correlation_runs (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at               TEXT NOT NULL,
    ended_at                 TEXT,
    wifi_visits_total        INTEGER,
    ble_visits_total         INTEGER,
    candidate_pairs          INTEGER,
    correlations_created     INTEGER,
    min_overlap_seconds      REAL,
    min_overlap_ratio        REAL,
    min_confidence           REAL,
    notes                    TEXT
);