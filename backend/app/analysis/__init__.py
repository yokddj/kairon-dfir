from importlib import import_module


__all__ = ["build_case_semi_auto_analysis"]


def __getattr__(name: str):
    if name != "build_case_semi_auto_analysis":
        raise AttributeError(name)
    module = import_module("app.analysis.semi_auto")
    value = getattr(module, name)
    globals()[name] = value
    return value
