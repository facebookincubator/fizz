#!/usr/bin/env python

# Copyright (c) 2018-present, Facebook, Inc.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

'fbcode_builder steps to build & test Fizz'

import specs.gmock as gmock
import specs.fmt as fmt
import specs.folly as folly
import specs.sodium as sodium

from shell_quoting import ShellQuoted


def fbcode_builder_spec(builder):
    builder.add_option(
        'fizz/_build:cmake_defines',
        {
            'BUILD_SHARED_LIBS': 'OFF',
            'BUILD_TESTS': 'ON',
        }
    )
    return {
        'depends_on': [gmock, fmt, folly, sodium],
        'steps': [
            builder.fb_github_cmake_install('fizz/_build', '../fizz', 'facebookincubator'),
            builder.step(
                'Run fizz tests', [
                    builder.run(
                        ShellQuoted('ctest --output-on-failure -j {n}')
                        .format(n=builder.option('make_parallelism'), )
                    )
                ]
            ),
        ]
    }


config = {
    'github_project': 'facebookincubator/fizz',
    'fbcode_builder_spec': fbcode_builder_spec,
}
