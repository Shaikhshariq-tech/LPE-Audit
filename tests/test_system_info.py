from core.system_info import collect_system_info


def test_system_info_returns_expected_keys():
    info = collect_system_info()

    for key in (
        "hostname",
        "operating_system",
        "platform",
        "architecture",
        "kernel_release",
        "username",
        "is_root",
        "is_linux",
    ):
        assert key in info


def test_system_info_uses_expected_types():
    info = collect_system_info()
    assert isinstance(info["hostname"], str)
    assert isinstance(info["is_root"], bool)
    assert isinstance(info["is_linux"], bool)
