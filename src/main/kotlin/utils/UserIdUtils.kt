package moe.tlaster.kotlinpgp.utils

import moe.tlaster.kotlinpgp.data.UserId
import java.util.regex.Pattern

internal object UserIdUtils {

    private val USER_ID_PATTERN = Pattern.compile("^(.*?)(?: \\((.*)\\))?(?: <(.*)>)?$")

    private val EMAIL_PATTERN = Pattern.compile("^<?\"?([^<>\"]*@[^<>\"]*\\.[^<>\"]*)\"?>?$")

    /**
     * Splits userId string into naming part, email part, and comment part.
     * See SplitUserIdTest for examples.
     */
    fun splitUserId(userId: String): UserId {
        if (!userId.isEmpty()) {
            val matcher = USER_ID_PATTERN.matcher(userId)
            if (matcher.matches()) {
                var name = if (matcher.group(1).isEmpty()) null else matcher.group(1)
                val comment = matcher.group(2)
                var email = matcher.group(3)
                if (email != null && name != null) {
                    val emailMatcher = EMAIL_PATTERN.matcher(name)
                    if (emailMatcher.matches() && email == emailMatcher.group(1)) {
                        email = emailMatcher.group(1)
                        name = null
                    }
                }
                if (email == null && name != null) {
                    val emailMatcher = EMAIL_PATTERN.matcher(name)
                    if (emailMatcher.matches()) {
                        email = emailMatcher.group(1)
                        name = null
                    }
                }
                return UserId(name, email, comment)
            }
        }
        return UserId(null, null, null)
    }

    /**
     * Returns a composed user id. Returns null if name, email and comment are empty.
     */
    fun createUserId(userId: UserId): String {
        val userIdBuilder = StringBuilder()
        if (!userId.name.isNullOrEmpty()) {
            userIdBuilder.append(userId.name)
        }
        if (!userId.comment.isNullOrEmpty()) {
            userIdBuilder.append(" (")
            userIdBuilder.append(userId.comment)
            userIdBuilder.append(")")
        }
        if (!userId.email.isNullOrEmpty()) {
            userIdBuilder.append(" <")
            userIdBuilder.append(userId.email)
            userIdBuilder.append(">")
        }
        return if (userIdBuilder.isEmpty()) "" else userIdBuilder.toString()
    }
}