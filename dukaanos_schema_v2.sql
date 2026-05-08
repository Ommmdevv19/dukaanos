-- =============================================
--  DukaanOS — Final Database Schema (v2)
--  Multi-tenant · Single schema · Normalized
--  store_id is the isolation key across all tables
-- =============================================

CREATE DATABASE IF NOT EXISTS dukaanos;
USE dukaanos;

-- =========================================
-- 1. USERS & AUTH
--    A user is a person who owns one or more
--    stores. Auth and identity are separate
--    from the store itself.
-- =========================================

CREATE TABLE users (
    user_id     BIGINT        AUTO_INCREMENT PRIMARY KEY,
    first_name  VARCHAR(50)   NOT NULL,
    last_name   VARCHAR(50),
    is_active   BOOLEAN       DEFAULT TRUE,
    created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE user_credentials (
    credential_id  BIGINT        AUTO_INCREMENT PRIMARY KEY,
    user_id        BIGINT        NOT NULL,
    phone_number   VARCHAR(15)   NOT NULL UNIQUE,
    email          VARCHAR(100)  UNIQUE,
    password_hash  VARCHAR(255)  NOT NULL,
    created_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE user_contact_verification (
    verification_id  BIGINT       AUTO_INCREMENT PRIMARY KEY,
    user_id          BIGINT       NOT NULL,
    type             ENUM('phone','email') NOT NULL,
    otp_hash         VARCHAR(255)   NOT NULL,
    is_verified      BOOLEAN      DEFAULT FALSE,
    expires_at       TIMESTAMP    NOT NULL,
    created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE login_sessions (
    session_id   BIGINT        AUTO_INCREMENT PRIMARY KEY,
    user_id      BIGINT        NOT NULL,
    login_time   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    logout_time  TIMESTAMP     NULL,
    ip_address   VARCHAR(45),
    device_info  VARCHAR(255),
    status       ENUM('SUCCESS','FAILED') NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- =========================================
-- 2. STORES
--    One user can own multiple stores.
--    store_id is the tenant key — every table
--    that belongs to a store references it.
-- =========================================

CREATE TABLE stores (
    store_id      BIGINT        AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT        NOT NULL,
    store_name    VARCHAR(100)  NOT NULL,
    location      VARCHAR(255),
    pincode       VARCHAR(10),
    gst_number    VARCHAR(20),
    fssai_number  VARCHAR(20),
    is_active     BOOLEAN       DEFAULT TRUE,
    created_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);


-- New category in categories page
CREATE TABLE categories (
    category_id  BIGINT        AUTO_INCREMENT PRIMARY KEY,
    store_id     BIGINT        NOT NULL,
    name         VARCHAR(100)  NOT NULL,
    description  VARCHAR(255),
    created_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (store_id) REFERENCES stores(store_id) ON DELETE CASCADE
);


-- Add item to category in categories page
CREATE TABLE items (
    item_id         BIGINT        AUTO_INCREMENT PRIMARY KEY,
    store_id        BIGINT        NOT NULL,
    category_id     BIGINT        NOT NULL,
    item_name       VARCHAR(100)  NOT NULL,
    brand           VARCHAR(100)  NOT NULL,
    gst_percentage  DECIMAL(5,2)  DEFAULT 0.00,
    created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (store_id)    REFERENCES stores(store_id)         ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(category_id)  ON DELETE CASCADE
);


-- Total stock and its prices are here in this table
-- the prices stored in this table are general and showed on the billing and godown page
-- whenever stock is added, then wholesale_price and selling_price will get average here and stock is added in this table, so it shows total quantity available
-- only one entry for every item of category which shows total quantity and avg prices
CREATE TABLE stock (
    stock_id        BIGINT        AUTO_INCREMENT PRIMARY KEY,
	category_id		BIGINT 		  NOT NULL,
    item_id         BIGINT        NOT NULL,
	current_quantity  DECIMAL(10,2) NOT NULL DEFAULT 0,
    wholesale_price DECIMAL(10,2) NOT NULL,
    selling_price   DECIMAL(10,2) NOT NULL,
	created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id)     REFERENCES items(item_id)           ON DELETE CASCADE,
    FOREIGN KEY (category_id) REFERENCES categories(category_id)  ON DELETE CASCADE
);


-- =========================================
-- 7. STOCK ENTRIES
--    Every time stock is received (via the
--    "Add Stock" screen), a row is added here.
--    This is the history log. The quantity
--    added here also increments stock.current_quantity.
--
--    purchase_price: what you paid (wholesale)
--    This is the price at time of THIS restock,
--    which may differ from current item_prices.
-- =========================================
-- this is audit log type table for Add Stock page
CREATE TABLE stock_entries (
    entry_id        BIGINT        AUTO_INCREMENT PRIMARY KEY,
    stock_id        BIGINT        NOT NULL,
    quantity_added  DECIMAL(10,2) NOT NULL,
    purchase_price  DECIMAL(10,2),
    selling_price   DECIMAL(10,2),
    supplier        VARCHAR(100),
    notes           VARCHAR(500),
    created_at      TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stock_id) REFERENCES stock(stock_id) ON DELETE CASCADE
);

-- =========================================
-- 8. BILLING
--    A bill belongs to a store. store_id here
--    lets you directly fetch all bills for a
--    store without joins.
--
--    total_amount  = sum of (qty × price) before GST
--    total_gst     = sum of all GST amounts
--    discount      = any manual discount applied
--    final_amount  = what the customer actually pays
-- =========================================

CREATE TABLE bills (
    bill_id          BIGINT        AUTO_INCREMENT PRIMARY KEY,
    store_id         BIGINT        NOT NULL,
    bill_number      VARCHAR(50)   NOT NULL UNIQUE,
    total_amount     DECIMAL(10,2) NOT NULL,
    total_gst        DECIMAL(10,2) DEFAULT 0,
    discount_amount  DECIMAL(10,2) DEFAULT 0,
    final_amount     DECIMAL(10,2) NOT NULL,
    status           ENUM('COMPLETED','CANCELLED') DEFAULT 'COMPLETED',
    created_at       TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (store_id) REFERENCES stores(store_id) ON DELETE CASCADE
);

-- =========================================
-- 9. BILL ITEMS
--    One row per product line in the bill.
--
--    price_at_sale: snapshot of selling_price
--    at the moment of billing. Even if you
--    update item_prices later, this bill will
--    always show the correct historical price.
--
--    gst_percentage: snapshot from items.gst_percentage
--    at time of sale. Same reason — audit safety.
--
--    total_price = (price_at_sale × quantity) + gst_amount
-- =========================================

CREATE TABLE bill_items (
    bill_item_id    BIGINT        AUTO_INCREMENT PRIMARY KEY,
    bill_id         BIGINT        NOT NULL,
	category_id		BIGINT 		  NOT NULL,
    item_id         BIGINT        NOT NULL,
    quantity        DECIMAL(10,2) NOT NULL,
    price_at_sale   DECIMAL(10,2) NOT NULL,
    gst_percentage  DECIMAL(5,2),
    gst_amount      DECIMAL(10,2),
    total_price     DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (bill_id)  REFERENCES bills(bill_id) ON DELETE CASCADE,
    FOREIGN KEY (item_id)  REFERENCES items(item_id) ON DELETE CASCADE
);

-- =========================================
-- 10. PAYMENTS
--     How the bill was paid. Supports split
--     payments (UPI + Cash) via multiple rows
--     for the same bill_id.
-- =========================================

CREATE TABLE payments (
    payment_id       BIGINT        AUTO_INCREMENT PRIMARY KEY,
    bill_id          BIGINT        NOT NULL,
    method           ENUM('UPI','CASH','OTHER') NOT NULL,
    amount           DECIMAL(10,2) NOT NULL,
    upi_reference    VARCHAR(100),
    cash_received    DECIMAL(10,2),
    change_returned  DECIMAL(10,2),
    note             VARCHAR(255),
    created_at       TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bill_id) REFERENCES bills(bill_id) ON DELETE CASCADE
);

-- =========================================
-- 11. DAILY METRICS (DASHBOARD)
--     Pre-aggregated numbers for the dashboard.
--     Avoids recalculating totals every page load.
--     One row per store per day.
-- =========================================

CREATE TABLE daily_metrics (
    metric_id          BIGINT        AUTO_INCREMENT PRIMARY KEY,
    store_id           BIGINT        NOT NULL,
    date               DATE          NOT NULL,
    total_sales        DECIMAL(12,2) DEFAULT 0,
    total_profit       DECIMAL(12,2) DEFAULT 0,
    total_transactions INT           DEFAULT 0,
    top_item_id        BIGINT,
    UNIQUE KEY uq_store_date (store_id, date),
    FOREIGN KEY (store_id)    REFERENCES stores(store_id) ON DELETE CASCADE,
    FOREIGN KEY (top_item_id) REFERENCES items(item_id)   ON DELETE SET NULL
);

-- =========================================
-- 12. AUDIT TABLES
--     Immutable logs. Never updated, only
--     inserted. Used for tracking security
--     events and data changes over time.
-- =========================================

CREATE TABLE audit_login (
    audit_id     BIGINT        AUTO_INCREMENT PRIMARY KEY,
    user_id      BIGINT,
    phone_number VARCHAR(15),
    status       ENUM('SUCCESS','FAILED'),
    ip_address   VARCHAR(45),
    device_info  VARCHAR(255),
    created_at   TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE audit_password_changes (
    audit_id   BIGINT        AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT        NOT NULL,
    changed_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE audit_contact_changes (
    audit_id   BIGINT        AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT        NOT NULL,
    old_phone  VARCHAR(15),
    new_phone  VARCHAR(15),
    old_email  VARCHAR(100),
    new_email  VARCHAR(100),
    verified   BOOLEAN       DEFAULT FALSE,
    changed_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE audit_profile_changes (
    audit_id      BIGINT        AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT        NOT NULL,
    field_changed VARCHAR(50),
    old_value     VARCHAR(255),
    new_value     VARCHAR(255),
    changed_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE audit_stock_changes (
    audit_id      BIGINT        AUTO_INCREMENT PRIMARY KEY,
    item_id       BIGINT        NOT NULL,
    old_quantity  DECIMAL(10,2),
    new_quantity  DECIMAL(10,2),
    change_type   ENUM('ADD','REMOVE','SALE'),
    reference_id  BIGINT,
    created_at    TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES items(item_id) ON DELETE CASCADE
);

CREATE TABLE audit_price_changes (
    audit_id   BIGINT        AUTO_INCREMENT PRIMARY KEY,
    item_id    BIGINT        NOT NULL,
    old_price  DECIMAL(10,2),
    new_price  DECIMAL(10,2),
    changed_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES items(item_id) ON DELETE CASCADE
);

-- =============================================
-- END OF SCHEMA — DukaanOS v2
-- =============================================
