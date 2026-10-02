"""Bounded persistence errors safe to map at application boundaries."""


class PersistenceError(RuntimeError):
    """Base class for failures inside a persistence implementation."""


class DatabaseUnavailable(PersistenceError):
    pass


class DatabaseBusy(PersistenceError):
    pass


class DatabaseVersionUnsupported(PersistenceError):
    pass


class PersistenceConflict(PersistenceError):
    pass


class PersistenceIntegrityError(PersistenceError):
    pass
