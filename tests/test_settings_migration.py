from PyQt6.QtCore import QSettings

from NetInfoView.settings import migrate_legacy_settings


def _ini(path):
    return QSettings(str(path), QSettings.Format.IniFormat)


def test_copies_old_settings_into_an_empty_new_store(tmp_path):
    legacy = _ini(tmp_path / "old.ini")
    legacy.setValue("ping_interval_seconds", 5)
    legacy.setValue("dark_background", True)
    legacy.sync()
    store = _ini(tmp_path / "new.ini")
    assert migrate_legacy_settings(store, legacy)
    assert store.value("ping_interval_seconds") in (5, "5")
    assert sorted(store.allKeys()) == sorted(legacy.allKeys())


def test_leaves_an_existing_new_store_alone(tmp_path):
    legacy = _ini(tmp_path / "old.ini")
    legacy.setValue("ping_interval_seconds", 5)
    store = _ini(tmp_path / "new.ini")
    store.setValue("ping_interval_seconds", 2)
    assert not migrate_legacy_settings(store, legacy)
    assert store.value("ping_interval_seconds") in (2, "2")


def test_nothing_to_copy(tmp_path):
    store = _ini(tmp_path / "new.ini")
    assert not migrate_legacy_settings(store, _ini(tmp_path / "old.ini"))
    assert store.allKeys() == []
