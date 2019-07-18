import pytest
import virtool.jobs.fastqc


@pytest.mark.parametrize("paired", [True, False])
def test_run_fastqc(paired, mocker):
    read_paths = [
        "/reads/reads_1.fq.gz"
    ]

    if paired:
        read_paths.append("/reads/reads_2.fq.gz")

    m_run_subprocess = mocker.stub()

    virtool.jobs.fastqc.run_fastqc(
        m_run_subprocess,
        4,
        read_paths,
        "/foo/bar/fastqc"
    )

    expected = [
        "fastqc",
        "-f", "fastq",
        "-o", "/foo/bar/fastqc",
        "-t", "4",
        "--extract",
        "/reads/reads_1.fq.gz"
    ]

    if paired:
        expected.append("/reads/reads_2.fq.gz")

    m_run_subprocess.assert_called_with(expected)
