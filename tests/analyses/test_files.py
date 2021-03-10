from sqlalchemy import select

import virtool.analyses.files

from virtool.analyses.models import AnalysisFile


async def test_create_nuvs_analysis_files(tmpdir, pg, pg_session):
    test_dir = tmpdir.mkdir("analyses")
    test_dir.join("assembly.fa.gz").write("FASTA file")
    test_dir.join("hmm.tsv").write("HMM file")

    await virtool.analyses.files.create_nuvs_analysis_files(pg, "foo", ["assembly.fa", "hmm.tsv"], test_dir)

    rows = list()
    async with pg_session as session:
        files = (await session.execute(select(AnalysisFile))).scalars().all()
        for file in files:
            rows.append(file.to_dict())

    assert rows == [
        {
            'id': 1,
            'analysis': 'foo',
            'description': None,
            'format': 'fasta',
            'name': 'assembly.fa.gz',
            'name_on_disk': '1-assembly.fa.gz',
            'size': 10,
            'uploaded_at': None
        },
        {
            'id': 2,
            'analysis': 'foo',
            'description': None,
            'format': 'tsv',
            'name': 'hmm.tsv',
            'name_on_disk': '2-hmm.tsv',
            'size': 8,
            'uploaded_at': None
        }
    ]