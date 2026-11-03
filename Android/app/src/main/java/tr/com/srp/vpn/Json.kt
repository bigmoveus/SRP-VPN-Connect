package tr.com.srp.vpn

import kotlin.math.abs
import kotlin.math.floor

/**
 * Strict JSON, as NSJSONSerialization reads and writes it on iOS: objects are LinkedHashMap<String, Any>,
 * arrays ArrayList<Any>, numbers Long or Double, and a JSON null is [Json.Null] so that it differs from a missing key.
 */
object Json {
    object Null {
        override fun toString() = "null"
    }

    class SyntaxError(val reason: String, val offset: Int) : Exception(reason)

    fun parse(text: String): Any {
        val parser = Parser(text)
        val value = parser.value(0)
        parser.skipSpace()
        if (parser.position != text.length) throw SyntaxError("Unexpected text after the JSON value.", parser.position)
        return value
    }

    /** The parsed value, or null when the text is not valid JSON. */
    fun parseOrNull(text: String?): Any? = if (text == null) null else try {
        parse(text)
    } catch (_: SyntaxError) {
        null
    }

    fun write(value: Any?, pretty: Boolean = false, sortedKeys: Boolean = false): String =
        StringBuilder().also { append(it, value, pretty, sortedKeys, 0) }.toString()

    private fun append(out: StringBuilder, value: Any?, pretty: Boolean, sorted: Boolean, depth: Int) {
        when (value) {
            null, Null -> out.append("null")
            is Boolean -> out.append(value)
            is String -> quote(out, value)
            is Number -> number(out, value)
            is Map<*, *> -> {
                val keys = value.keys.map { it as String }.let { if (sorted) it.sorted() else it }
                out.append('{')
                keys.forEachIndexed { index, key ->
                    if (index > 0) out.append(',')
                    if (pretty) newline(out, depth + 1)
                    quote(out, key)
                    out.append(if (pretty) " : " else ":")
                    append(out, value[key], pretty, sorted, depth + 1)
                }
                if (pretty) newline(out, if (keys.isEmpty()) 0 else depth).also { if (keys.isEmpty()) out.append("\n") }
                out.append('}')
            }
            is List<*> -> {
                out.append('[')
                value.forEachIndexed { index, item ->
                    if (index > 0) out.append(',')
                    if (pretty) newline(out, depth + 1)
                    append(out, item, pretty, sorted, depth + 1)
                }
                if (pretty) newline(out, if (value.isEmpty()) 0 else depth).also { if (value.isEmpty()) out.append("\n") }
                out.append(']')
            }
            else -> throw IllegalArgumentException("Not a JSON value: $value")
        }
    }

    private fun newline(out: StringBuilder, depth: Int) {
        out.append('\n')
        repeat(depth) { out.append("  ") }
    }

    private fun number(out: StringBuilder, value: Number) {
        val double = value.toDouble()
        if (value is Long || value is Int) out.append(value.toLong())
        else if (double == floor(double) && abs(double) < 1e15) out.append(double.toLong())
        else out.append(double)
    }

    private fun quote(out: StringBuilder, text: String) {
        out.append('"')
        for (character in text) {
            when {
                character == '"' -> out.append("\\\"")
                character == '\\' -> out.append("\\\\")
                character == '\n' -> out.append("\\n")
                character == '\r' -> out.append("\\r")
                character == '\t' -> out.append("\\t")
                character < ' ' -> out.append("\\u%04x".format(character.code))
                else -> out.append(character)
            }
        }
        out.append('"')
    }

    private class Parser(val text: String) {
        var position = 0

        fun skipSpace() {
            while (position < text.length && text[position] in " \t\r\n") position++
        }

        fun value(depth: Int): Any {
            if (depth > 512) throw SyntaxError("Too many nested arrays or objects.", position)
            skipSpace()
            if (position >= text.length) throw SyntaxError("Unexpected end of text.", position)
            return when (text[position]) {
                '{' -> objectValue(depth)
                '[' -> arrayValue(depth)
                '"' -> stringValue()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", Null)
                else -> numberValue()
            }
        }

        private fun literal(word: String, result: Any): Any {
            if (!text.startsWith(word, position)) throw SyntaxError("Invalid value.", position)
            position += word.length
            return result
        }

        private fun objectValue(depth: Int): Any {
            val result = LinkedHashMap<String, Any>()
            position++
            skipSpace()
            if (position < text.length && text[position] == '}') {
                position++
                return result
            }
            while (true) {
                skipSpace()
                if (position >= text.length || text[position] != '"') throw SyntaxError("Expected a string key.", position)
                val key = stringValue()
                skipSpace()
                if (position >= text.length || text[position] != ':') throw SyntaxError("Expected ':' after the key.", position)
                position++
                result[key] = value(depth + 1)
                skipSpace()
                if (position >= text.length) throw SyntaxError("Unexpected end of text in an object.", position)
                when (text[position++]) {
                    ',' -> continue
                    '}' -> return result
                    else -> throw SyntaxError("Expected ',' or '}' in an object.", position - 1)
                }
            }
        }

        private fun arrayValue(depth: Int): Any {
            val result = ArrayList<Any>()
            position++
            skipSpace()
            if (position < text.length && text[position] == ']') {
                position++
                return result
            }
            while (true) {
                result.add(value(depth + 1))
                skipSpace()
                if (position >= text.length) throw SyntaxError("Unexpected end of text in an array.", position)
                when (text[position++]) {
                    ',' -> continue
                    ']' -> return result
                    else -> throw SyntaxError("Expected ',' or ']' in an array.", position - 1)
                }
            }
        }

        private fun stringValue(): String {
            val out = StringBuilder()
            position++
            while (true) {
                if (position >= text.length) throw SyntaxError("Unterminated string.", position)
                val character = text[position++]
                when {
                    character == '"' -> return out.toString()
                    character < ' ' -> throw SyntaxError("Unescaped control character in a string.", position - 1)
                    character == '\\' -> {
                        if (position >= text.length) throw SyntaxError("Unterminated string.", position)
                        when (val escape = text[position++]) {
                            '"', '\\', '/' -> out.append(escape)
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                val digits = text.substring(position, minOf(position + 4, text.length))
                                val code = digits.takeIf { it.length == 4 }?.toIntOrNull(16)
                                    ?: throw SyntaxError("Invalid \\u escape.", position)
                                out.append(code.toChar())
                                position += 4
                            }
                            else -> throw SyntaxError("Invalid escape sequence.", position - 1)
                        }
                    }
                    else -> out.append(character)
                }
            }
        }

        private fun numberValue(): Any {
            val start = position
            if (position < text.length && text[position] == '-') position++
            val digits = position
            while (position < text.length && text[position].isAsciiDigit()) position++
            val whole = position - digits
            if (whole == 0 || (whole > 1 && text[digits] == '0')) throw SyntaxError("Invalid value.", start)
            var integer = true
            if (position < text.length && text[position] == '.') {
                integer = false
                position++
                val fraction = position
                while (position < text.length && text[position].isAsciiDigit()) position++
                if (position == fraction) throw SyntaxError("Invalid number.", start)
            }
            if (position < text.length && text[position] in "eE") {
                integer = false
                position++
                if (position < text.length && text[position] in "+-") position++
                val exponent = position
                while (position < text.length && text[position].isAsciiDigit()) position++
                if (position == exponent) throw SyntaxError("Invalid number.", start)
            }
            val token = text.substring(start, position)
            return (if (integer) token.toLongOrNull() else null) ?: token.toDouble()
        }

        private fun Char.isAsciiDigit() = this in '0'..'9'
    }
}
