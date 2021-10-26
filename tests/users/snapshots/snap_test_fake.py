# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import GenericRepr, Snapshot


snapshots = Snapshot()

snapshots['test_create_fake_bob_user[uvloop] 1'] = {
    '_id': 'abc123',
    'administrator': True,
    'force_reset': False,
    'groups': [
    ],
    'handle': 'bob',
    'invalidate_sessions': True,
    'last_password_change': GenericRepr('datetime.datetime(2015, 10, 6, 20, 0)'),
    'permissions': {
        'cancel_job': False,
        'create_ref': False,
        'create_sample': False,
        'modify_hmm': False,
        'modify_subtraction': False,
        'remove_file': False,
        'remove_job': False,
        'upload_file': False
    },
    'primary_group': '',
    'settings': {
        'quick_analyze_workflow': 'pathoscope_bowtie',
        'show_ids': True,
        'show_versions': True,
        'skip_quick_analyze_dialog': True
    }
}
