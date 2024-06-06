#!/bin/bash
# (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.


if [ "$GITHUB_ACTIONS" == "true" ]; then
    ./buck2 build //fizz/...
else
    dotslash-oss "$BUCK2" build //... && dotslash-oss "$BUCK2" test //...
fi
