from secure_req_check.parser.requirements import parse_requirements


def test_parse_exact_versions(sample_req_file):
    packages = parse_requirements(str(sample_req_file))
    assert len(packages) == 3
    assert packages[0].name == "django"
    assert packages[0].version == "3.2.12"
    assert packages[1].name == "requests"
    assert packages[1].version == "2.25.0"
    assert packages[2].name == "flask"
    assert packages[2].version == "0.12.2"


def test_parse_empty_file(tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("")
    packages = parse_requirements(str(empty_file))
    assert packages == []


def test_parse_comments_only(tmp_path):
    comments_file = tmp_path / "comments.txt"
    comments_file.write_text("# just a comment\n# another line")
    packages = parse_requirements(str(comments_file))
    assert packages == []