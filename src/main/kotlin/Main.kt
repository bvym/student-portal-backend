import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.http.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.client.plugins.contentnegotiation.*
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import com.google.auth.oauth2.GoogleCredentials
import java.io.File
import java.io.FileInputStream
import org.mindrot.jbcrypt.BCrypt

@Serializable
data class ChangePasswordResponse(
    val success: Boolean,
    val message: String
)

// Data classes
@Serializable
data class LoginRequest(
    val username: String,
    val password: String
)

@Serializable
data class ChangePasswordRequest(
    val username: String,
    val oldPassword: String,
    val newPassword: String
)

@Serializable
data class LoginResponse(
    val success: Boolean,
    val mustChangePassword: Boolean = false,
    val message: String? = null,
    val studentData: StudentData? = null
)

@Serializable
data class StudentData(
    val name: String,
    val username: String,
    val cookieDecorating: String,
    val hauntedBasement: String,
    val clubFair: String,
    val openHouse: String,
    val mentalHealthOct8: String,
    val mentalHealthNov14: String,
    val fallPlay: String,
    val spiritWeek: String,
    val septCosa: String,
    val octCosa: String,
    val novCosa: String,
    val decCosa: String,
    val totalPoints: String,
    val percentOutOf90: String
)

@Serializable
data class UserAccount(
    val username: String,
    val passwordHash: String
)

@Serializable
data class UsersDatabase(
    val users: MutableMap<String, UserAccount> = mutableMapOf()
)

// Google Sheets API Response
@Serializable
data class SheetsResponse(
    val range: String? = null,
    val majorDimension: String? = null,
    val values: List<List<String>>? = null
)

// File storage for changed passwords
class UserStorage {
    private val file = File("users.json")
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }

    fun load(): UsersDatabase {
        return if (file.exists()) {
            json.decodeFromString(file.readText())
        } else {
            UsersDatabase()
        }
    }

    fun save(db: UsersDatabase) {
        file.writeText(json.encodeToString(db))
    }

    fun hasChangedPassword(username: String): Boolean {
        return load().users.containsKey(username.lowercase())
    }

    fun getUser(username: String): UserAccount? {
        return load().users[username.lowercase()]
    }

    fun saveNewPassword(username: String, newPassword: String) {
        val db = load()
        db.users[username.lowercase()] = UserAccount(
            username = username.lowercase(),
            passwordHash = BCrypt.hashpw(newPassword, BCrypt.gensalt())
        )
        save(db)
    }

    fun removeUser(username: String) {
        val db = load()
        db.users.remove(username.lowercase())
        save(db)
    }
}

val userStorage = UserStorage()

// HTTP client for Google Sheets API
val httpClient = HttpClient(CIO) {
    install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true })
    }
}

// Get OAuth token from service account
fun getAccessToken(): String {
    // Try Render's secret file location first, then local file
    val credentialsPath = if (File("/etc/secrets/points-portal-478302-cd5cd63d4fc1.json").exists()) {
        "/etc/secrets/points-portal-478302-cd5cd63d4fc1.json"
    } else {
        "points-portal-478302-cd5cd63d4fc1.json"
    }

    val credentials = GoogleCredentials.fromStream(
        FileInputStream(credentialsPath)
    ).createScoped(listOf("https://www.googleapis.com/auth/spreadsheets.readonly"))

    credentials.refreshIfExpired()
    return credentials.accessToken.tokenValue
}

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
            })
        }

        // CORS for frontend
        install(CORS) {
            anyHost()
            allowHeader(HttpHeaders.ContentType)
            allowHeader("X-Admin-Key")  // Allow custom admin header
            allowMethod(HttpMethod.Post)
            allowMethod(HttpMethod.Get)
            allowMethod(HttpMethod.Options)  // Allow preflight requests
        }

        routing {
            get("/") {
                call.respondText("Student Portal API is running! ✅")
            }

            post("/api/login") {
                val request = call.receive<LoginRequest>()
                val username = request.username.lowercase().trim()

                // Check if user has already changed their password
                val hasChanged = userStorage.hasChangedPassword(username)

                if (hasChanged) {
                    // User has changed password - check against users.json
                    val user = userStorage.getUser(username)

                    if (user == null || !BCrypt.checkpw(request.password, user.passwordHash)) {
                        call.respond(HttpStatusCode.Unauthorized, LoginResponse(
                            success = false,
                            message = "Invalid username or password"
                        ))
                        return@post
                    }

                    // Password correct, fetch their data
                    val studentData = getStudentDataFromSheets(username)

                    if (studentData == null) {
                        call.respond(HttpStatusCode.NotFound, LoginResponse(
                            success = false,
                            message = "Student data not found"
                        ))
                        return@post
                    }

                    call.respond(HttpStatusCode.OK, LoginResponse(
                        success = true,
                        mustChangePassword = false,
                        studentData = studentData
                    ))

                } else {
                    // First time login - check temp password from Google Sheet
                    val sheetData = getStudentRowFromSheets(username)

                    if (sheetData == null) {
                        call.respond(HttpStatusCode.Unauthorized, LoginResponse(
                            success = false,
                            message = "Invalid username or password"
                        ))
                        return@post
                    }

                    val tempPassword = sheetData["tempPassword"] ?: ""

                    if (request.password != tempPassword) {
                        call.respond(HttpStatusCode.Unauthorized, LoginResponse(
                            success = false,
                            message = "Invalid username or password"
                        ))
                        return@post
                    }

                    // Temp password correct - force them to change it
                    val studentData = sheetData["data"] as? StudentData

                    call.respond(HttpStatusCode.OK, LoginResponse(
                        success = true,
                        mustChangePassword = true,
                        studentData = studentData
                    ))
                }
            }

            post("/api/change-password") {
                val request = call.receive<ChangePasswordRequest>()
                val username = request.username.lowercase().trim()

                // Validate new password
                if (request.newPassword.length < 6) {
                    call.respond(HttpStatusCode.BadRequest, ChangePasswordResponse(
                        success = false,
                        message = "Password must be at least 6 characters"
                    ))
                    return@post
                }

                // Verify old password first
                val hasChanged = userStorage.hasChangedPassword(username)

                val oldPasswordValid = if (hasChanged) {
                    // Check against stored hash
                    val user = userStorage.getUser(username)
                    user != null && BCrypt.checkpw(request.oldPassword, user.passwordHash)
                } else {
                    // Check against temp password in sheet
                    val sheetData = getStudentRowFromSheets(username)
                    val tempPassword = sheetData?.get("tempPassword") ?: ""
                    request.oldPassword == tempPassword
                }

                if (!oldPasswordValid) {
                    call.respond(HttpStatusCode.Unauthorized, ChangePasswordResponse(
                        success = false,
                        message = "Current password is incorrect"
                    ))
                    return@post
                }

                // Save new password
                userStorage.saveNewPassword(username, request.newPassword)

                call.respond(HttpStatusCode.OK, ChangePasswordResponse(
                    success = true,
                    message = "Password changed successfully"
                ))
            }

            // ADMIN: Reset a student's password (revert to temp password)
            post("/api/admin/reset-password") {
                val adminKey = call.request.headers["X-Admin-Key"]
                val correctKey = System.getenv("ADMIN_KEY") ?: "change-this-secret-key"

                if (adminKey != correctKey) {
                    call.respond(HttpStatusCode.Forbidden, ChangePasswordResponse(
                        success = false,
                        message = "Invalid admin key"
                    ))
                    return@post
                }

                @Serializable
                data class ResetRequest(val username: String)

                val request = call.receive<ResetRequest>()
                val username = request.username.lowercase().trim()

                // Remove from users.json - they'll use temp password again
                userStorage.removeUser(username)

                call.respond(HttpStatusCode.OK, ChangePasswordResponse(
                    success = true,
                    message = "Password reset. Student must use temp password from sheet."
                ))
            }
        }
    }.start(wait = true)
}

// Get student data from Google Sheets using REST API
suspend fun getStudentDataFromSheets(username: String): StudentData? {
    val row = getStudentRowFromSheets(username)
    return row?.get("data") as? StudentData
}

// Get full student row including temp password via HTTP
suspend fun getStudentRowFromSheets(username: String): Map<String, Any>? {
    try {
        println("DEBUG: Looking for username: $username")
        val token = getAccessToken()
        val spreadsheetId = "15TB4GGs4y_8-_nkKvAJTs_s1lAmSpHjodYnnuiDrVhs"
        val range = "'Semester 1'!A:Q"  // Quote the sheet name

        val url = "https://sheets.googleapis.com/v4/spreadsheets/$spreadsheetId/values/${range.replace(" ", "%20")}"

        println("DEBUG: Fetching from URL: $url")
        val response: HttpResponse = httpClient.get(url) {
            header("Authorization", "Bearer $token")
        }

        val responseText = response.bodyAsText()
        println("DEBUG: Response status: ${response.status}")
        println("DEBUG: Response body: ${responseText.take(500)}") // First 500 chars

        val sheetsResponse = Json.decodeFromString<SheetsResponse>(responseText)
        val values = sheetsResponse.values

        if (values == null) {
            println("DEBUG: No values found in sheet")
            return null
        }

        println("DEBUG: Found ${values.size} rows in sheet")

        // Find row with matching username (column B, index 1)
        for (i in 1 until values.size) {
            val row = values[i]
            if (row.size >= 2) {
                val sheetUsername = row[1].trim().lowercase()
                println("DEBUG: Row $i - Username in sheet: '$sheetUsername', Looking for: '${username.lowercase()}'")

                if (sheetUsername == username.lowercase()) {
                    println("DEBUG: MATCH FOUND at row $i")
                    println("DEBUG: Row data: $row")

                    val studentData = StudentData(
                        name = row.getOrNull(0) ?: "",
                        username = row.getOrNull(1) ?: "",
                        cookieDecorating = row.getOrNull(2) ?: "0",
                        hauntedBasement = row.getOrNull(3) ?: "0",
                        clubFair = row.getOrNull(4) ?: "0",
                        openHouse = row.getOrNull(5) ?: "0",
                        mentalHealthOct8 = row.getOrNull(6) ?: "",
                        mentalHealthNov14 = row.getOrNull(7) ?: "",
                        fallPlay = row.getOrNull(8) ?: "0",
                        spiritWeek = row.getOrNull(9) ?: "0",
                        septCosa = row.getOrNull(10) ?: "",
                        octCosa = row.getOrNull(11) ?: "",
                        novCosa = row.getOrNull(12) ?: "",
                        decCosa = row.getOrNull(13) ?: "",
                        totalPoints = row.getOrNull(14) ?: "0",
                        percentOutOf90 = row.getOrNull(15) ?: "0%"
                    )

                    // Column Q (index 16) is the temp password
                    val tempPassword = row.getOrNull(16) ?: ""
                    println("DEBUG: Temp password from sheet: '$tempPassword'")

                    return mapOf(
                        "data" to studentData,
                        "tempPassword" to tempPassword
                    )
                }
            }
        }

        println("DEBUG: No matching username found")
        return null
    } catch (e: Exception) {
        println("DEBUG: ERROR - ${e.message}")
        e.printStackTrace()
        return null
    }
}