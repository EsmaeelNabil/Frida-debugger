package models

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.lang.Exception


@Serializable
data class ApplicationsResponse(
    val applications: List<Application>
) {
    companion object {
        fun getApplications(jsonString: String): List<Application> {
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
data class Application(
    val identifier: String = "",
    val name: String = "",
    val parameters: Parameters = Parameters(),
    val pid: Int = 0
)

@Serializable
data class Parameters(
    val build: String = "",
    val dataDir: String = "",
    val debuggable: Boolean? = false,
    val ppid: Int? = 0,
    val sources: List<String> = listOf(),
    val started: String? = "",
    val targetSdk: Int = 0,
    val user: String? = "",
    val version: String = ""
)