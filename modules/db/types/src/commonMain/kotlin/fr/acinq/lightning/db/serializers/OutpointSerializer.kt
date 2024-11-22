/*
 * Copyright 2024 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.lightning.db.serializers

import fr.acinq.bitcoin.OutPoint
import fr.acinq.bitcoin.TxHash
import fr.acinq.lightning.db.serializers.primitives.AbstractStringSerializer

class OutpointSerializer : AbstractStringSerializer<OutPoint>(
    name = "Outpoint",
    fromString = { it.split(":").run { OutPoint(hash = TxHash(first()), index = last().toLong()) } },
    toString = { outpoint -> "${outpoint.hash}:${outpoint.index}" }
)