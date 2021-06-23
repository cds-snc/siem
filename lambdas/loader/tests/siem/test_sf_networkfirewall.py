from siem import sf_networkfirewall


def test_transform():
    data = {"event": {"event_type": "foo"}, "network": {"transport": "TCP"}}
    result = sf_networkfirewall.transform(data)
    assert result == {"event": {"event_type": "foo"}, "network": {"transport": "TCP"}}


def test_transform_event_type_alert():
    data = {"event": {"event_type": "alert"}, "network": {"transport": "TCP"}}
    result = sf_networkfirewall.transform(data)
    assert result == {
        "event": {
            "event_type": "alert",
            "kind": "alert",
            "category": "intrusion_detection",
        },
        "network": {"transport": "TCP"},
    }
