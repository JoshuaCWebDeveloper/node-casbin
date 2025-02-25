// Copyright 2019 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import { DefaultLogger } from './defaultLogger';
let logger = new DefaultLogger();
// setLogger sets the current logger.
function setLogger(l) {
    logger = l;
}
// getLogger returns the current logger.
function getLogger() {
    return logger;
}
// logPrint prints the log.
function logPrint(...v) {
    logger.print(...v);
}
// logPrintf prints the log with the format.
function logPrintf(format, ...v) {
    logger.printf(format, ...v);
}
export { setLogger, getLogger, logPrint, logPrintf };
