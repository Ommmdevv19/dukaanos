-- ============================================================
--  DukaanOS — FK Fix Migration (robust version)
--  Run this ONCE in your MySQL client:
--    mysql -u root -p dukaanos < migrate_fix_fk.sql
-- ============================================================

USE dukaanos;
SET FOREIGN_KEY_CHECKS = 0;

-- ── Step 1: Drop broken FK on stock.category_id ─────────────
-- The schema had: REFERENCES category(category_id) [wrong table name]
-- Correct table is: categories
SET @fk_stock_cat = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = 'dukaanos'
      AND TABLE_NAME   = 'stock'
      AND COLUMN_NAME  = 'category_id'
      AND REFERENCED_TABLE_NAME IS NOT NULL
    LIMIT 1
);
SET @sql = IF(
    @fk_stock_cat IS NOT NULL,
    CONCAT('ALTER TABLE stock DROP FOREIGN KEY `', @fk_stock_cat, '`'),
    'SELECT "No category_id FK on stock — already clean" AS info'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

ALTER TABLE stock
    ADD CONSTRAINT fk_stock_category
        FOREIGN KEY (category_id) REFERENCES categories(category_id)
        ON DELETE CASCADE;

-- ── Step 2: Drop phantom created_by FK on stock_entries ─────
-- The schema declared a FK on created_by but never defined the column.
SET @fk_se_cb = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = 'dukaanos'
      AND TABLE_NAME   = 'stock_entries'
      AND COLUMN_NAME  = 'created_by'
      AND REFERENCED_TABLE_NAME IS NOT NULL
    LIMIT 1
);
SET @sql = IF(
    @fk_se_cb IS NOT NULL,
    CONCAT('ALTER TABLE stock_entries DROP FOREIGN KEY `', @fk_se_cb, '`'),
    'SELECT "No created_by FK on stock_entries — already clean" AS info'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ── Step 3: Drop phantom created_by FK on bills ─────────────
SET @fk_bills_cb = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = 'dukaanos'
      AND TABLE_NAME   = 'bills'
      AND COLUMN_NAME  = 'created_by'
      AND REFERENCED_TABLE_NAME IS NOT NULL
    LIMIT 1
);
SET @sql = IF(
    @fk_bills_cb IS NOT NULL,
    CONCAT('ALTER TABLE bills DROP FOREIGN KEY `', @fk_bills_cb, '`'),
    'SELECT "No created_by FK on bills — already clean" AS info'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET FOREIGN_KEY_CHECKS = 1;

SELECT 'Migration complete. Stock inserts should now work.' AS status;

-- ── Step 4: Fix bill_items FK — add ON DELETE CASCADE ────────
-- The original FK had no action (defaults to RESTRICT), which
-- blocks item deletion when that item appeared in any bill.
-- We drop the old FK and re-add it with ON DELETE CASCADE.
SET @fk_bi_item = (
    SELECT CONSTRAINT_NAME
    FROM information_schema.KEY_COLUMN_USAGE
    WHERE TABLE_SCHEMA = 'dukaanos'
      AND TABLE_NAME   = 'bill_items'
      AND COLUMN_NAME  = 'item_id'
      AND REFERENCED_TABLE_NAME IS NOT NULL
    LIMIT 1
);
SET @sql = IF(
    @fk_bi_item IS NOT NULL,
    CONCAT('ALTER TABLE bill_items DROP FOREIGN KEY `', @fk_bi_item, '`'),
    'SELECT "No item_id FK on bill_items — already clean" AS info'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

ALTER TABLE bill_items
    ADD CONSTRAINT fk_bill_items_item
        FOREIGN KEY (item_id) REFERENCES items(item_id)
        ON DELETE CASCADE;

SELECT 'Step 4 complete: bill_items item_id FK now has ON DELETE CASCADE.' AS status;
