
package com.example.mobilesecuritythreatanalyzer

import android.app.Activity
import android.os.Bundle
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.content.res.ColorStateList
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : Activity() {

    private val permissionChecks = mutableMapOf<String, CheckBox>()

    private lateinit var resultView: TextView
    private lateinit var analyzeButton: Button
    private lateinit var resultBadge: TextView
    private lateinit var resultTitle: TextView

    // Modern Navy + Cyan Theme
    private val navy = Color.rgb(12, 25, 48)
    private val navyLight = Color.rgb(23, 43, 72)
    private val cyan = Color.rgb(0, 210, 230)
    private val backgroundColor = Color.rgb(241, 246, 251)
    private val cardWhite = Color.WHITE
    private val darkText = Color.rgb(25, 42, 65)
    private val secondaryText = Color.rgb(105, 123, 145)

    private val permissionDescriptions = linkedMapOf(
        "CAMERA" to Pair(
            "Camera Access",
            "Access camera for photo and video capture"
        ),
        "RECORD_AUDIO" to Pair(
            "Microphone Access",
            "Record audio using the microphone"
        ),
        "ACCESS_FINE_LOCATION" to Pair(
            "Precise Location",
            "Access your device's precise location"
        ),
        "READ_CONTACTS" to Pair(
            "Contacts Access",
            "Read contacts stored on the device"
        ),
        "READ_SMS" to Pair(
            "SMS Access",
            "Read SMS messages from the device"
        ),
        "READ_CALL_LOG" to Pair(
            "Call History",
            "Access call history information"
        ),
        "READ_MEDIA_IMAGES" to Pair(
            "Photo & Image Access",
            "Access images stored on the device"
        ),
        "INTERNET" to Pair(
            "Internet Access",
            "Connect to online services and servers"
        )
    )

    private val apiUrl =
        "https://ai-mobile-security-threat-analyzer-api.onrender.com/analyze"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        createDashboard()
    }

    private fun dp(value: Int): Int {
        return (value * resources.displayMetrics.density).toInt()
    }

    private fun roundedBackground(
        color: Int,
        radius: Int
    ): GradientDrawable {
        return GradientDrawable().apply {
            setColor(color)
            cornerRadius = dp(radius).toFloat()
        }
    }

    private fun gradientBackground(): GradientDrawable {
        return GradientDrawable(
            GradientDrawable.Orientation.TL_BR,
            intArrayOf(navy, navyLight)
        ).apply {
            cornerRadius = dp(22).toFloat()
        }
    }

    private fun createText(
        textValue: String,
        size: Float,
        color: Int,
        bold: Boolean = false
    ): TextView {

        return TextView(this).apply {
            text = textValue
            textSize = size
            setTextColor(color)

            if (bold) {
                setTypeface(null, Typeface.BOLD)
            }
        }
    }

    private fun addSpace(
        parent: LinearLayout,
        height: Int
    ) {
        parent.addView(
            View(this),
            LinearLayout.LayoutParams(
                1,
                dp(height)
            )
        )
    }

    private fun createDashboard() {

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(backgroundColor)
        }

        val scrollView = ScrollView(this).apply {
            isFillViewport = true
            isVerticalScrollBarEnabled = false
        }

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(
                dp(18),
                dp(18),
                dp(18),
                dp(28)
            )
        }

        // HEADER CARD

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = gradientBackground()
            setPadding(
                dp(22),
                dp(25),
                dp(22),
                dp(25)
            )
        }

        val topLabel = TextView(this).apply {
            text = "◈  MOBILE SECURITY SYSTEM"
            textSize = 12f
            setTextColor(cyan)
            setTypeface(null, Typeface.BOLD)
            letterSpacing = 0.08f
        }

        header.addView(topLabel)

        addSpace(header, 18)

        val title = createText(
            "AI Mobile Security\nThreat Analyzer",
            27f,
            Color.WHITE,
            true
        )

        header.addView(title)

        addSpace(header, 12)

        val subtitle = createText(
            "Analyze permission risks and identify potential security concerns.",
            14f,
            Color.rgb(204, 220, 238)
        )

        header.addView(subtitle)

        addSpace(header, 20)

        val status = TextView(this).apply {
            text = "●  ONLINE ANALYSIS ENABLED"
            textSize = 11f
            setTextColor(cyan)
            setTypeface(null, Typeface.BOLD)
            background = roundedBackground(
                Color.rgb(30, 57, 83),
                20
            )
            setPadding(
                dp(13),
                dp(9),
                dp(13),
                dp(9)
            )
        }

        header.addView(status)

        content.addView(
            header,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )

        addSpace(content, 25)

        // PERMISSION SECTION

        content.addView(
            createText(
                "Security Permissions",
                21f,
                darkText,
                true
            )
        )

        addSpace(content, 5)

        content.addView(
            createText(
                "Select the permissions you want to analyze.",
                13f,
                secondaryText
            )
        )

        addSpace(content, 16)

        permissionDescriptions.forEach { (permission, details) ->

            val card = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                background = roundedBackground(
                    cardWhite,
                    15
                )
                setPadding(
                    dp(12),
                    dp(12),
                    dp(12),
                    dp(12)
                )
                elevation = dp(2).toFloat()
            }

            val checkBox = CheckBox(this).apply {
                buttonTintList = ColorStateList(
                    arrayOf(
                        intArrayOf(android.R.attr.state_checked),
                        intArrayOf()
                    ),
                    intArrayOf(
                        cyan,
                        secondaryText
                    )
                )

                isClickable = true
            }

            permissionChecks[permission] = checkBox

            val textContainer = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(
                    dp(8),
                    dp(3),
                    0,
                    dp(3)
                )
            }

            val permissionTitle = createText(
                details.first,
                15f,
                darkText,
                true
            )

            val permissionDescription = createText(
                details.second,
                12f,
                secondaryText
            )

            textContainer.addView(permissionTitle)

            addSpace(textContainer, 4)

            textContainer.addView(permissionDescription)

            card.addView(
                checkBox,
                LinearLayout.LayoutParams(
                    dp(42),
                    dp(48)
                )
            )

            card.addView(
                textContainer,
                LinearLayout.LayoutParams(
                    0,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    1f
                )
            )

            card.setOnClickListener {
                checkBox.isChecked = !checkBox.isChecked
            }

            content.addView(
                card,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = dp(11)
                }
            )
        }

        addSpace(content, 10)

        // ANALYZE BUTTON

        analyzeButton = Button(this).apply {
            text = "ANALYZE SECURITY RISKS"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(navy)
            isAllCaps = false
            background = roundedBackground(cyan, 14)
            elevation = dp(4).toFloat()

            setPadding(
                dp(12),
                dp(12),
                dp(12),
                dp(12)
            )

            setOnClickListener {
                analyzeSelection()
            }
        }

        content.addView(
            analyzeButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(58)
            )
        )

        addSpace(content, 28)

        // RESULTS SECTION

        content.addView(
            createText(
                "Analysis Results",
                21f,
                darkText,
                true
            )
        )

        addSpace(content, 13)

        val resultCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBackground(
                cardWhite,
                18
            )
            setPadding(
                dp(18),
                dp(19),
                dp(18),
                dp(19)
            )
            elevation = dp(2).toFloat()
        }

        val resultHeader = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        resultTitle = createText(
            "Security Report",
            17f,
            darkText,
            true
        )

        resultHeader.addView(
            resultTitle,
            LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1f
            )
        )

        resultBadge = TextView(this).apply {
            text = "WAITING"
            textSize = 10f
            setTypeface(null, Typeface.BOLD)
            setTextColor(secondaryText)
            background = roundedBackground(
                backgroundColor,
                20
            )
            setPadding(
                dp(12),
                dp(7),
                dp(12),
                dp(7)
            )
        }

        resultHeader.addView(resultBadge)

        resultCard.addView(resultHeader)

        addSpace(resultCard, 15)

        resultView = createText(
            "Your security analysis will appear here.\n\nSelect permissions above and tap Analyze Security Risks to get your report.",
            14f,
            secondaryText
        ).apply {
            setLineSpacing(dp(5).toFloat(), 1f)
        }

        resultCard.addView(resultView)

        content.addView(
            resultCard,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )

        addSpace(content, 18)

        // DISCLAIMER

        val disclaimerCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedBackground(
                Color.rgb(226, 239, 250),
                14
            )
            setPadding(
                dp(15),
                dp(15),
                dp(15),
                dp(15)
            )
        }

        disclaimerCard.addView(
            createText(
                "ⓘ  SECURITY NOTICE",
                12f,
                navy,
                true
            )
        )

        addSpace(disclaimerCard, 7)

        disclaimerCard.addView(
            createText(
                "Permission indicators alone cannot prove an app is malicious. This prototype does not automatically scan installed apps or inspect their behavior.",
                12f,
                Color.rgb(69, 91, 116)
            )
        )

        content.addView(disclaimerCard)

        addSpace(content, 18)

        val footer = createText(
            "AI MOBILE SECURITY THREAT ANALYZER  •  VERSION 1.0",
            10f,
            secondaryText,
            true
        ).apply {
            gravity = Gravity.CENTER
        }

        content.addView(footer)

        scrollView.addView(content)

        root.addView(
            scrollView,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT
            )
        )

        setContentView(root)
    }

    // EXISTING BACKEND ANALYSIS LOGIC

    private fun analyzeSelection() {

        val selected = permissionChecks
            .filterValues { it.isChecked }
            .keys
            .toList()

        if (selected.isEmpty()) {
            resultBadge.text = "SELECT REQUIRED"
            resultView.text =
                "Please select at least one permission before starting the security analysis."
            return
        }

        analyzeButton.isEnabled = false
        analyzeButton.text = "ANALYZING..."
        resultBadge.text = "PROCESSING"

        resultView.text =
            "Connecting to security analysis server...\n\nPlease wait while your permissions are being analyzed."

        Thread {

            var connection: HttpURLConnection? = null

            try {

                connection = (
                    URL(apiUrl).openConnection() as HttpURLConnection
                ).apply {

                    requestMethod = "POST"
                    connectTimeout = 30000
                    readTimeout = 60000
                    doOutput = true

                    setRequestProperty(
                        "Content-Type",
                        "application/json; charset=UTF-8"
                    )

                    setRequestProperty(
                        "Accept",
                        "application/json"
                    )
                }

                val requestBody = JSONObject().apply {
                    put(
                        "permissions",
                        JSONArray(selected)
                    )
                }

                connection.outputStream.use { output ->

                    output.write(
                        requestBody.toString()
                            .toByteArray(Charsets.UTF_8)
                    )
                }

                val statusCode = connection.responseCode

                val responseStream =
                    if (statusCode in 200..299) {
                        connection.inputStream
                    } else {
                        connection.errorStream
                    }

                val responseText =
                    responseStream?.bufferedReader()?.use {
                        it.readText()
                    } ?: throw Exception(
                        "The server returned an empty response."
                    )

                if (statusCode !in 200..299) {
                    throw Exception(
                        "Server error: HTTP $statusCode"
                    )
                }

                val response = JSONObject(responseText)

                val score = response.getInt("risk_score")
                val level = response.getString("risk_level")

                val permissions =
                    response.getJSONArray("permissions_analyzed")

                val findings =
                    response.getJSONArray("findings")

                val disclaimerText = response.optString(
                    "disclaimer",
                    "Permission indicators alone do not prove malicious behavior."
                )

                val result = buildString {

                    append("RISK LEVEL\n")
                    append("$level\n\n")

                    append("RISK SCORE\n")
                    append("$score / 100\n\n")

                    append("PERMISSIONS ANALYZED\n")

                    for (i in 0 until permissions.length()) {
                        append("• ${permissions.getString(i)}\n")
                    }

                    append("\nSECURITY FINDINGS\n\n")

                    for (i in 0 until findings.length()) {

                        val finding = findings.getJSONObject(i)

                        append(
                            "• ${finding.getString("permission")}\n"
                        )

                        append(
                            "  Severity: ${finding.getString("severity")}\n"
                        )

                        append(
                            "  ${finding.getString("message")}\n\n"
                        )
                    }

                    append("DISCLAIMER\n")
                    append(disclaimerText)
                }

                runOnUiThread {

                    resultView.text = result

                    resultBadge.text = level.uppercase()

                    resultBadge.setTextColor(
                        when (level.uppercase()) {
                            "HIGH" -> Color.rgb(190, 40, 50)
                            "MEDIUM" -> Color.rgb(185, 115, 0)
                            "LOW" -> Color.rgb(20, 130, 90)
                            else -> navy
                        }
                    )

                    resultBadge.background = roundedBackground(
                        when (level.uppercase()) {
                            "HIGH" -> Color.rgb(255, 229, 231)
                            "MEDIUM" -> Color.rgb(255, 243, 218)
                            "LOW" -> Color.rgb(221, 246, 235)
                            else -> backgroundColor
                        },
                        20
                    )

                    resultTitle.text = "Security Report"
                }

            } catch (e: Exception) {

                runOnUiThread {

                    resultBadge.text = "ERROR"

                    resultView.text =
                        "Analysis failed.\n\n" +
                        "${e.message ?: "Please try again."}\n\n" +
                        "Check your internet connection and try again."
                }

            } finally {

                connection?.disconnect()

                runOnUiThread {

                    analyzeButton.isEnabled = true
                    analyzeButton.text = "ANALYZE SECURITY RISKS"
                }
            }

        }.start()
    }
}
