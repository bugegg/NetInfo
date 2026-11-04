"""Runs the asyncio ping engine on its own thread and bridges it to Qt signals."""

from __future__ import annotations

import asyncio

from PyQt6.QtCore import QThread, pyqtSignal

from ..ping.engine import EngineOptions, PingEngine, PingTarget


class EngineThread(QThread):
    """Owns one PingEngine for the duration of a ping session."""

    #: list[tuple[int, PingResult]] — emitted from this thread, queued to the GUI.
    results_ready = pyqtSignal(list)
    round_started = pyqtSignal(int)
    finished_pinging = pyqtSignal()

    def __init__(self, targets: list[PingTarget], options: EngineOptions) -> None:
        super().__init__()
        self._targets = targets
        self._options = options
        self._engine: PingEngine | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def run(self) -> None:  # noqa: D102 - QThread entry point
        asyncio.run(self._main())

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        engine = PingEngine(
            on_results=self.results_ready.emit,
            on_round_complete=self.round_started.emit,
        )
        engine.set_targets(self._targets)
        engine.set_options(self._options)
        self._engine = engine
        try:
            await engine.run()
        finally:
            self._engine = None
            self._loop = None
            self.finished_pinging.emit()

    # -- control from the GUI thread ---------------------------------------

    def _call(self, func, *args) -> None:
        """Hand work to the engine's loop; ignore it if the loop has gone."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(func, *args)
        except RuntimeError:
            pass

    def stop_pinging(self) -> None:
        engine = self._engine
        if engine is not None:
            self._call(engine.stop)

    def update_options(self, options: EngineOptions) -> None:
        engine = self._engine
        if engine is not None:
            self._call(engine.set_options, options)

    def update_targets(self, targets: list[PingTarget]) -> None:
        engine = self._engine
        if engine is not None:
            self._call(engine.set_targets, targets)
