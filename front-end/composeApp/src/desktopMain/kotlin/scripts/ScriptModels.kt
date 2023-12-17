package scripts

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class NamesListModel(
    @SerialName("script")
    val scriptName: String,
    val value: String
)