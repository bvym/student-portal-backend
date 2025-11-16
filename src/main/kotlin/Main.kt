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
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import java.sql.Connection

// Data classes
@Serializable
data class ChangePasswordResponse(
    val success: Boolean,
    val message: String
)

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

@Serializable
data class SheetsResponse(
    val range: String? = null,
    val majorDimension: String? = null,
    val values: List<List<String>>? = null
)

// Database connection pool with fallback to file storage
object DatabaseConnection {
    private var dataSource: HikariDataSource? = null

    fun init() {
        val databaseUrl = System.getenv("DATABASE_URL")

        if (databaseUrl == null) {
            println("⚠️  No DATABASE_URL found - using file storage (passwords will reset on redeploy)")
            return
        }

        try {
            println("🔌 Connecting to database...")
            println("📝 Raw DATABASE_URL format: ${databaseUrl.substringBefore("://")}")

            // Fix: Ensure the URL has the jdbc:postgresql:// prefix
            var jdbcUrl = if (databaseUrl.startsWith("jdbc:")) {
                databaseUrl
            } else if (databaseUrl.startsWith("postgresql://")) {
                "jdbc:$databaseUrl"
            } else if (databaseUrl.startsWith("postgres://")) {
                databaseUrl.replace("postgres://", "jdbc:postgresql://")
            } else {
                "jdbc:postgresql://$databaseUrl"
            }

            // Add SSL and connection parameters if not present
            // Use sslmode=require but don't verify the certificate (common for Supabase)
            if (!jdbcUrl.contains("?")) {
                jdbcUrl += "?sslmode=require"
            } else if (!jdbcUrl.contains("sslmode")) {
                jdbcUrl += "&sslmode=require"
            }

            // Remove any existing ssl=true parameter and add proper SSL settings
            jdbcUrl = jdbcUrl.replace("&ssl=true", "").replace("?ssl=true&", "?")

            println("📝 Using JDBC URL: ${jdbcUrl.replace(Regex(":[^:@]+@"), ":****@")}")

            val config = HikariConfig().apply {
                this.jdbcUrl = jdbcUrl
                maximumPoolSize = 3
                minimumIdle = 1
                connectionTimeout = 30000
                idleTimeout = 600000
                maxLifetime = 1800000
                isAutoCommit = false
                transactionIsolation = "TRANSACTION_REPEATABLE_READ"

                // SSL properties for Supabase
                addDataSourceProperty("ssl", "true")
                addDataSourceProperty("sslmode", "require")

                // Connection timeouts
                addDataSourceProperty("socketTimeout", "30")
                addDataSourceProperty("loginTimeout", "30")
                addDataSourceProperty("connectTimeout", "30")

                validate()
            }

            dataSource = HikariDataSource(config)

            // Create table if not exists
            getConnection().use { conn ->
                conn.createStatement().execute("""
                    CREATE TABLE IF NOT EXISTS user_passwords (
                        username VARCHAR(255) PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
            }
            println("✅ Database connected successfully!")
        } catch (e: Exception) {
            println("❌ Database connection failed: ${e.message}")
            e.printStackTrace()
            println("⚠️  Falling back to file storage")
            dataSource = null
        }
    }

    fun getConnection(): Connection {
        return dataSource?.connection ?: throw IllegalStateException("Database not available")
    }

    fun isAvailable(): Boolean = dataSource != null
}

// Storage for passwords - supports both database and file
class PasswordStorage {
    private val file = File("users.json")
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }

    private fun loadFromFile(): UsersDatabase {
        return if (file.exists()) {
            try {
                json.decodeFromString(file.readText())
            } catch (e: Exception) {
                UsersDatabase()
            }
        } else {
            UsersDatabase()
        }
    }

    private fun saveToFile(db: UsersDatabase) {
        file.writeText(json.encodeToString(db))
    }

    fun hasChangedPassword(username: String): Boolean {
        return if (DatabaseConnection.isAvailable()) {
            try {
                DatabaseConnection.getConnection().use { conn ->
                    val stmt = conn.prepareStatement("SELECT 1 FROM user_passwords WHERE username = ?")
                    stmt.setString(1, username.lowercase())
                    val rs = stmt.executeQuery()
                    rs.next()
                }
            } catch (e: Exception) {
                false
            }
        } else {
            loadFromFile().users.containsKey(username.lowercase())
        }
    }

    fun getUser(username: String): UserAccount? {
        return if (DatabaseConnection.isAvailable()) {
            try {
                DatabaseConnection.getConnection().use { conn ->
                    val stmt = conn.prepareStatement("SELECT password_hash FROM user_passwords WHERE username = ?")
                    stmt.setString(1, username.lowercase())
                    val rs = stmt.executeQuery()

                    if (rs.next()) {
                        UserAccount(
                            username = username.lowercase(),
                            passwordHash = rs.getString("password_hash")
                        )
                    } else null
                }
            } catch (e: Exception) {
                null
            }
        } else {
            loadFromFile().users[username.lowercase()]
        }
    }

    fun saveNewPassword(username: String, newPassword: String) {
        val hash = BCrypt.hashpw(newPassword, BCrypt.gensalt())

        if (DatabaseConnection.isAvailable()) {
            try {
                DatabaseConnection.getConnection().use { conn ->
                    val stmt = conn.prepareStatement("""
                        INSERT INTO user_passwords (username, password_hash, updated_at) 
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT (username) 
                        DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = CURRENT_TIMESTAMP
                    """)
                    stmt.setString(1, username.lowercase())
                    stmt.setString(2, hash)
                    stmt.executeUpdate()
                    conn.commit()
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        } else {
            val db = loadFromFile()
            db.users[username.lowercase()] = UserAccount(
                username = username.lowercase(),
                passwordHash = hash
            )
            saveToFile(db)
        }
    }

    fun removeUser(username: String) {
        if (DatabaseConnection.isAvailable()) {
            try {
                DatabaseConnection.getConnection().use { conn ->
                    val stmt = conn.prepareStatement("DELETE FROM user_passwords WHERE username = ?")
                    stmt.setString(1, username.lowercase())
                    stmt.executeUpdate()
                    conn.commit()
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        } else {
            val db = loadFromFile()
            db.users.remove(username.lowercase())
            saveToFile(db)
        }
    }
}

val passwordStorage = PasswordStorage()

// HTTP client for Google Sheets API
val httpClient = HttpClient(CIO) {
    install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true })
    }
}

fun getAccessToken(): String {
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
    // Initialize database (with file storage fallback)
    DatabaseConnection.init()

    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
            })
        }

        install(CORS) {
            anyHost()
            allowHeader(HttpHeaders.ContentType)
            allowHeader("X-Admin-Key")
            allowMethod(HttpMethod.Post)
            allowMethod(HttpMethod.Get)
            allowMethod(HttpMethod.Options)
        }

        routing {
            get("/") {
                call.respondText("Student Portal API is running! ✅")
            }

            post("/api/login") {
                val request = call.receive<LoginRequest>()
                val username = request.username.lowercase().trim()

                val hasChanged = passwordStorage.hasChangedPassword(username)

                if (hasChanged) {
                    val user = passwordStorage.getUser(username)

                    if (user == null || !BCrypt.checkpw(request.password, user.passwordHash)) {
                        call.respond(HttpStatusCode.Unauthorized, LoginResponse(
                            success = false,
                            message = "Invalid username or password"
                        ))
                        return@post
                    }

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

                if (request.newPassword.length < 6) {
                    call.respond(HttpStatusCode.BadRequest, ChangePasswordResponse(
                        success = false,
                        message = "Password must be at least 6 characters"
                    ))
                    return@post
                }

                val hasChanged = passwordStorage.hasChangedPassword(username)

                val oldPasswordValid = if (hasChanged) {
                    val user = passwordStorage.getUser(username)
                    user != null && BCrypt.checkpw(request.oldPassword, user.passwordHash)
                } else {
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

                passwordStorage.saveNewPassword(username, request.newPassword)

                call.respond(HttpStatusCode.OK, ChangePasswordResponse(
                    success = true,
                    message = "Password changed successfully"
                ))
            }

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

                passwordStorage.removeUser(username)

                call.respond(HttpStatusCode.OK, ChangePasswordResponse(
                    success = true,
                    message = "Password reset. Student must use temp password from sheet."
                ))
            }

            get("/api/admin/list-students") {
                val adminKey = call.request.headers["X-Admin-Key"]
                val correctKey = System.getenv("ADMIN_KEY") ?: "change-this-secret-key"

                if (adminKey != correctKey) {
                    call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Invalid admin key"))
                    return@get
                }

                val allStudents = getAllStudentsFromSheets()
                call.respond(HttpStatusCode.OK, mapOf("students" to allStudents))
            }

            post("/api/admin/view-student") {
                val adminKey = call.request.headers["X-Admin-Key"]
                val correctKey = System.getenv("ADMIN_KEY") ?: "change-this-secret-key"

                if (adminKey != correctKey) {
                    call.respond(HttpStatusCode.Forbidden, LoginResponse(
                        success = false,
                        message = "Invalid admin key"
                    ))
                    return@post
                }

                @Serializable
                data class ViewStudentRequest(val username: String)

                val request = call.receive<ViewStudentRequest>()
                val studentData = getStudentDataFromSheets(request.username)

                if (studentData == null) {
                    call.respond(HttpStatusCode.NotFound, LoginResponse(
                        success = false,
                        message = "Student not found"
                    ))
                    return@post
                }

                call.respond(HttpStatusCode.OK, LoginResponse(
                    success = true,
                    studentData = studentData
                ))
            }
        }
    }.start(wait = true)
}

suspend fun getStudentDataFromSheets(username: String): StudentData? {
    val row = getStudentRowFromSheets(username)
    return row?.get("data") as? StudentData
}

suspend fun getAllStudentsFromSheets(): List<Map<String, String>> {
    try {
        val token = getAccessToken()
        val spreadsheetId = "15TB4GGs4y_8-_nkKvAJTs_s1lAmSpHjodYnnuiDrVhs"
        val range = "'Semester 1'!A:B"

        val url = "https://sheets.googleapis.com/v4/spreadsheets/$spreadsheetId/values/${range.replace(" ", "%20")}"

        val response: HttpResponse = httpClient.get(url) {
            header("Authorization", "Bearer $token")
        }

        val sheetsResponse = Json.decodeFromString<SheetsResponse>(response.bodyAsText())
        val values = sheetsResponse.values ?: return emptyList()

        return values.drop(1).mapNotNull { row ->
            if (row.size >= 2) {
                mapOf(
                    "name" to row[0],
                    "username" to row[1]
                )
            } else null
        }
    } catch (e: Exception) {
        e.printStackTrace()
        return emptyList()
    }
}

suspend fun getStudentRowFromSheets(username: String): Map<String, Any>? {
    try {
        println("DEBUG: Looking for username: $username")
        val token = getAccessToken()
        val spreadsheetId = "15TB4GGs4y_8-_nkKvAJTs_s1lAmSpHjodYnnuiDrVhs"
        val range = "'Semester 1'!A:Q"

        val url = "https://sheets.googleapis.com/v4/spreadsheets/$spreadsheetId/values/${range.replace(" ", "%20")}"

        println("DEBUG: Fetching from URL: $url")
        val response: HttpResponse = httpClient.get(url) {
            header("Authorization", "Bearer $token")
        }

        val responseText = response.bodyAsText()
        println("DEBUG: Response status: ${response.status}")
        println("DEBUG: Response body: ${responseText.take(500)}")

        val sheetsResponse = Json.decodeFromString<SheetsResponse>(responseText)
        val values = sheetsResponse.values

        if (values == null) {
            println("DEBUG: No values found in sheet")
            return null
        }

        println("DEBUG: Found ${values.size} rows in sheet")

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