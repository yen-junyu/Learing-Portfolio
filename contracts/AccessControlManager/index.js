/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const accessControlManager = require('./lib/AccessControlManager');

module.exports.AccessControlManager = accessControlManager;
module.exports.contracts = [accessControlManager];


