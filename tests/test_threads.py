"""Quitting waits for the worker threads still running (ui/threads.py), so
Qt never destroys one mid-run and aborts the app."""

import time

import pytest
from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QApplication

from NetInfoView.ui import threads


@pytest.fixture(scope="session")
def qapp():
    yield QApplication.instance() or QApplication([])


class Busy(QThread):
    """Works until asked to stop, as the monitors do."""

    def __init__(self) -> None:
        super().__init__()
        self.stopped = False

    def stop(self) -> None:
        self.stopped = True

    def run(self) -> None:
        while not self.stopped:
            time.sleep(0.01)


def test_stop_all_stops_and_waits_for_tracked_and_retired_threads(qapp):
    kept, let_go = Busy(), Busy()
    threads.track(kept).start()
    let_go.start()
    threads.retire(let_go)
    assert kept.isRunning() and let_go.isRunning()
    assert threads.stop_all(2000)
    assert not kept.isRunning() and not let_go.isRunning()
    assert let_go.parent() is qapp


def test_stop_all_reports_a_thread_that_will_not_stop(qapp):
    class Stubborn(QThread):
        def run(self) -> None:
            time.sleep(0.5)

    thread = threads.track(Stubborn())
    thread.start()
    assert not threads.stop_all(50)
    assert thread.wait(2000)


def test_finished_threads_are_forgotten(qapp):
    thread = threads.track(Busy())
    thread.start()
    thread.stop()
    assert thread.wait(2000)
    QApplication.processEvents()
    assert thread not in threads._running
