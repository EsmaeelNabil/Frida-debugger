package models

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.lang.Exception

/**
 * This data class represents the applications response.
 * @property applications The list of applications.
 */
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

/**
 * This data class represents the application.
 * @property identifier The identifier of the application.
 * @property name The name of the application.
 * @property parameters The parameters of the application.
 * @property pid The process id of the application.
 */
@Serializable
data class Application(
    val identifier: String = "",
    val name: String = "",
    val parameters: Parameters = Parameters(),
    val pid: Int = 0
)

/**
 * This data class represents the parameters of the application.
 * @property build The build of the application.
 * @property dataDir The data directory of the application.
 * @property debuggable The debuggable state of the application.
 * @property ppid The parent process id of the application.
 * @property sources The sources of the application.
 * @property started The start time of the application.
 * @property targetSdk The target sdk of the application.
 * @property user The user of the application.
 * @property version The version of the application.
 */
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