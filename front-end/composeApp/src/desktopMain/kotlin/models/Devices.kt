package models

import kotlinx.serialization.Serializable

import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import java.lang.Exception


@Serializable
data class DevicesResponse(
    val devices: List<Device>
) {
    companion object {
        fun getDevices(jsonString: String): List<Device> {
            return try {
                // TODO: clean this
                Json {
                    ignoreUnknownKeys = true
                }.decodeFromString(jsonString)
            } catch (e: Exception) {
                println(e)
                listOf()
            }
        }
    }
}


@Serializable
data class Device(
    @SerialName("impl")
    val deviceDetails: DeviceDetails = DeviceDetails()
)

@Serializable
data class DeviceDetails(
    @SerialName("icon")
    val icon: Icon? = null,
    @SerialName("id")
    val id: String = "",
    @SerialName("isLost")
    val isLost: Boolean? = null,
    @SerialName("name")
    val name: String = "",
    @SerialName("type")
    val type: String = ""
)

@Serializable
data class Icon(
    @SerialName("format")
    val format: String,
    @SerialName("height")
    val height: Int,
    @SerialName("image")
    val image: List<Int>,
    @SerialName("width")
    val width: Int
)