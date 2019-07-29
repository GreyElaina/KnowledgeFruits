def AlternativeImport(Preference, Alternative=None):
    try:
        return __import__(Preference)
    except ImportError:
        if not Alternative:
            raise
        return __import__(Alternative)

