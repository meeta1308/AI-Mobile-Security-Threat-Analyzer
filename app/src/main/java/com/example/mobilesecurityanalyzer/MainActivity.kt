
package com.example.mobilesecuritythreatanalyzer

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.content.res.ColorStateList
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ImageView
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

    // Installed app selection
    private var selectedAppPackage: String? = null
    private var selectedAppName: String? = null
    private var selectedAppPermissions: List<String> = emptyList()
    private var selectedAppGrantedPermissions: Set<String> = emptySet()

    private lateinit var selectedAppView: TextView
    private lateinit var selectAppButton: Button
    private lateinit var clearAppButton: Button

    // Dark cyber-security palette
    private val navy = Color.rgb(7, 12, 29)
    private val navyLight = Color.rgb(17, 27, 54)
    private val panel = Color.rgb(20, 31, 59)
    private val panelRaised = Color.rgb(27, 41, 73)
    private val cyan = Color.rgb(53, 217, 255)
    private val purple = Color.rgb(157, 105, 255)
    private val backgroundColor = Color.rgb(8, 14, 32)
    private val cardWhite = Color.rgb(20, 31, 59)
    private val darkText = Color.rgb(239, 246, 255)
    private val secondaryText = Color.rgb(165, 181, 207)
    private val openingHandler = Handler(Looper.getMainLooper())
    private var openingRunnable: Runnable? = null

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
        window.statusBarColor = navy
        window.navigationBarColor = navy
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = 0
        if (savedInstanceState == null) showOpeningSequence() else createDashboard()
    }

    private fun showOpeningSequence() {
        showOpeningPage(showIntro = false)
        openingRunnable = Runnable {
            if (isFinishing || isDestroyed) return@Runnable
            showOpeningPage(showIntro = true)
            openingRunnable = Runnable {
                if (isFinishing || isDestroyed) return@Runnable
                createDashboard()
            }
            openingHandler.postDelayed(openingRunnable!!, 2000L)
        }
        openingHandler.postDelayed(openingRunnable!!, 2000L)
    }

    private fun showOpeningPage(showIntro: Boolean) {
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(28), dp(28), dp(28), dp(28))
            background = GradientDrawable(
                GradientDrawable.Orientation.TL_BR,
                intArrayOf(navy, Color.rgb(18, 25, 58), Color.rgb(30, 19, 65))
            )
        }
        val logo = ImageView(this).apply {
            setImageResource(R.drawable.app_logo)
            scaleType = ImageView.ScaleType.FIT_CENTER
            contentDescription = "AI Mobile Security Threat Analyzer logo"
            alpha = 0f
            scaleX = 0.78f
            scaleY = 0.78f
        }
        val logoSize = if (showIntro) 164 else 224
        page.addView(logo, LinearLayout.LayoutParams(dp(logoSize), dp(logoSize)))
        if (showIntro) {
            addSpace(page, 26)
            page.addView(createText("AI MOBILE SECURITY", 21f, Color.WHITE, true).apply {
                gravity = Gravity.CENTER
                letterSpacing = 0.10f
            })
            addSpace(page, 7)
            page.addView(createText("THREAT ANALYZER", 17f, cyan, true).apply {
                gravity = Gravity.CENTER
                letterSpacing = 0.16f
            })
            addSpace(page, 15)
            page.addView(createText("Smart analysis. Safer mobile experience.", 13f, secondaryText).apply {
                gravity = Gravity.CENTER
            })
        }
        setContentView(page)
        logo.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(650L).start()
        if (showIntro) {
            for (i in 1 until page.childCount) {
                page.getChildAt(i).alpha = 0f
                page.getChildAt(i).translationY = dp(12).toFloat()
                page.getChildAt(i).animate().alpha(1f).translationY(0f)
                    .setStartDelay(180L + i * 90L).setDuration(450L).start()
            }
        }
    }

    override fun onDestroy() {
        openingRunnable?.let { openingHandler.removeCallbacks(it) }
        openingHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
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
            Color.rgb(190, 207, 235)
        )

        header.addView(subtitle)
        addSpace(header, 20)

        val status = TextView(this).apply {
            text = "●  ONLINE ANALYSIS ENABLED"
            textSize = 11f
            setTextColor(cyan)
            setTypeface(null, Typeface.BOLD)
            background = roundedBackground(
                Color.rgb(34, 48, 83),
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

        // INSTALLED APP SELECTION SECTION

        addSpace(content, 25)

        content.addView(
            createText(
                "Select Installed App",
                21f,
                darkText,
                true
            )
        )

        addSpace(content, 5)

        content.addView(
            createText(
                "Choose an installed launcher app to inspect its declared permissions.",
                13f,
                secondaryText
            )
        )

        addSpace(content, 13)

        selectedAppView = createText(
            "No app selected. You can use manual permission analysis below.",
            13f,
            secondaryText
        )

        selectedAppView.setLineSpacing(dp(4).toFloat(), 1f)
        content.addView(selectedAppView)

        addSpace(content, 12)

        selectAppButton = Button(this).apply {
            text = "SELECT INSTALLED APP"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(navy)
            isAllCaps = false
            background = roundedBackground(cyan, 14)

            setOnClickListener {
                showInstalledApps()
            }
        }

        content.addView(
            selectAppButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(54)
            )
        )

        addSpace(content, 7)

        clearAppButton = Button(this).apply {
            text = "CLEAR APP SELECTION"
            textSize = 12f
            setTextColor(darkText)
            isAllCaps = false
            background = roundedBackground(
                Color.rgb(29, 43, 75),
                12
            )
            visibility = View.GONE

            setOnClickListener {
                clearSelectedApp()
            }
        }

        content.addView(
            clearAppButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(45)
            )
        )

        // PERMISSION SECTION

        addSpace(content, 25)

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
                "Select permissions manually, or select an installed app above.",
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
                    panel,
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
                if (checkBox.isEnabled) {
                    checkBox.isChecked = !checkBox.isChecked
                }
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
                panel,
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
            "Your security analysis will appear here.\n\nSelect permissions above or choose an installed app, then tap Analyze Security Risks.",
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
                Color.rgb(29, 43, 75),
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
                "Declared permissions indicate what an app requests, not necessarily what it currently uses. Permission indicators alone cannot prove that an app is malicious. This prototype does not monitor app behavior.",
                12f,
                Color.rgb(177, 193, 218)
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
        root.alpha = 0f
        root.animate().alpha(1f).setDuration(500L).start()
    }

    // INSTALLED APP LIST

    @Suppress("DEPRECATION")
    private fun showInstalledApps() {

        try {
            val intent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_LAUNCHER)
            }

            val installedApps: List<ResolveInfo> =
                packageManager.queryIntentActivities(intent, 0)
                    .distinctBy {
                        it.activityInfo.packageName
                    }
                    .sortedBy {
                        it.loadLabel(packageManager)
                            .toString()
                            .lowercase()
                    }

            if (installedApps.isEmpty()) {
                selectedAppView.text = "No launcher apps found."
                return
            }

            val appNames = installedApps.map {
                it.loadLabel(packageManager).toString()
            }.toTypedArray()

            AlertDialog.Builder(this)
                .setTitle("Select an Installed App")
                .setItems(appNames) { _, position ->

                    val appInfo = installedApps[position]

                    val appName =
                        appInfo.loadLabel(packageManager).toString()

                    val packageName =
                        appInfo.activityInfo.packageName

                    loadSelectedApp(packageName, appName)
                }
                .setNegativeButton("Cancel", null)
                .show()

        } catch (e: Exception) {

            selectedAppView.text =
                "Unable to load installed apps: ${e.message}"
        }
    }

    // READ SELECTED APP PERMISSIONS

    @Suppress("DEPRECATION")
    private fun loadSelectedApp(
        packageName: String,
        appName: String
    ) {

        try {

            val packageInfo: PackageInfo =
                if (android.os.Build.VERSION.SDK_INT >= 33) {

                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.PackageInfoFlags.of(
                            PackageManager.GET_PERMISSIONS.toLong()
                        )
                    )

                } else {

                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.GET_PERMISSIONS
                    )
                }

            val requestedPermissions =
                packageInfo.requestedPermissions ?: emptyArray()

            val permissionFlags =
                packageInfo.requestedPermissionsFlags ?: IntArray(0)

            val grantedPermissions = mutableSetOf<String>()

            requestedPermissions.forEachIndexed { index, permission ->

                val flags = permissionFlags.getOrNull(index) ?: 0

                if (
                    flags and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
                ) {
                    grantedPermissions.add(permission)
                }
            }

            selectedAppPackage = packageName
            selectedAppName = appName
            selectedAppPermissions = requestedPermissions.toList()
            selectedAppGrantedPermissions = grantedPermissions

            // Automatically update permission checkboxes

            permissionChecks.forEach { (permission, checkBox) ->

                val isRequested = requestedPermissions.any {
                    it.substringAfterLast('.') == permission
                }

                checkBox.isChecked = isRequested
                checkBox.isEnabled = false
            }

            val permissionSummary =
                if (requestedPermissions.isEmpty()) {
                    "No declared permissions found."
                } else {
                    requestedPermissions
                        .take(8)
                        .joinToString("\n") {
                            "• ${it.substringAfterLast('.')}"
                        } +
                        if (requestedPermissions.size > 8) {
                            "\n• And ${requestedPermissions.size - 8} more"
                        } else {
                            ""
                        }
                }

            selectedAppView.text =
                "Selected App: $appName\n" +
                "Package: $packageName\n" +
                "Declared permissions: ${requestedPermissions.size}\n" +
                "Granted permissions reported: ${grantedPermissions.size}\n\n" +
                permissionSummary

            clearAppButton.visibility = View.VISIBLE

            resultBadge.text = "APP SELECTED"
            resultBadge.setTextColor(cyan)

            resultView.text =
                "App selected successfully.\n\n" +
                "Tap Analyze Security Risks to analyze its supported permissions."

        } catch (e: Exception) {

            selectedAppView.text =
                "Unable to read app information: ${e.message}"

            selectedAppPackage = null
            selectedAppName = null
            selectedAppPermissions = emptyList()
            selectedAppGrantedPermissions = emptySet()

            clearAppButton.visibility = View.GONE
        }
    }

    // CLEAR SELECTED APP

    private fun clearSelectedApp() {

        selectedAppPackage = null
        selectedAppName = null
        selectedAppPermissions = emptyList()
        selectedAppGrantedPermissions = emptySet()

        // Reset and unlock all permission checkboxes

        permissionChecks.forEach { (_, checkBox) ->
            checkBox.isChecked = false
            checkBox.isEnabled = true
        }

        selectedAppView.text =
            "No app selected. You can use manual permission analysis below."

        clearAppButton.visibility = View.GONE

        resultBadge.text = "WAITING"
        resultBadge.setTextColor(secondaryText)

        resultView.text =
            "App selection cleared.\n\nYou can now select permissions manually."
    }

    // BACKEND ANALYSIS + GEMINI AI REPORT

    private fun analyzeSelection() {

        val appPackage = selectedAppPackage
        val appName = selectedAppName

        // Get selected permissions

        val selected: List<String> =
            if (appPackage != null) {

                selectedAppPermissions
                    .map {
                        it.substringAfterLast('.')
                    }
                    .filter {
                        permissionDescriptions.containsKey(it)
                    }
                    .distinct()

            } else {

                permissionChecks
                    .filterValues { it.isChecked }
                    .keys
                    .toList()
            }

        if (selected.isEmpty()) {

            resultBadge.text = "SELECT REQUIRED"

            resultView.text =
                if (appPackage != null) {
                    "The selected app does not declare any of the permissions supported by this analyzer.\n\n" +
                    "You can clear the app selection and use manual permission analysis."
                } else {
                    "Please select at least one permission before starting the security analysis."
                }

            return
        }

        analyzeButton.isEnabled = false
        analyzeButton.text = "ANALYZING..."
        resultBadge.text = "PROCESSING"

        resultView.text =
            "Connecting to security analysis server...\n\n" +
            "Please wait while the permissions are being analyzed."

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

                // Prepare permission status information

                val granted = selectedAppGrantedPermissions
                    .map {
                        it.substringAfterLast('.')
                    }
                    .filter {
                        it in selected
                    }

                val notGranted = selected.filter {
                    it !in granted
                }

                // Prepare backend request

                val requestBody = JSONObject().apply {

                    put(
                        "permissions",
                        JSONArray(selected)
                    )

                    if (appPackage != null) {

                        put(
                            "app_name",
                            appName ?: "Unknown App"
                        )

                        put(
                            "package_name",
                            appPackage
                        )

                        put(
                            "granted_permissions",
                            JSONArray(granted)
                        )

                        put(
                            "not_granted_permissions",
                            JSONArray(notGranted)
                        )
                    }
                }

                connection.outputStream.use { output ->

                    output.write(
                        requestBody.toString()
                            .toByteArray(Charsets.UTF_8)
                    )
                }

                // Read server response

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
                        "Server error: HTTP $statusCode\n$responseText"
                    )
                }

                val response = JSONObject(responseText)

                // Extract AI analysis results

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

                val aiSummary = response.optString(
                    "summary",
                    ""
                )

                val recommendations =
                    response.optJSONArray("recommendations")
                val permissionIntelligence =
                    response.optJSONArray("permission_intelligence")
                // Build final report

                val result = buildString {

                    if (appPackage != null) {

                        append("SELECTED APPLICATION\n")
                        append("$appName\n")
                        append("Package: $appPackage\n\n")

                        append("KEY PERMISSIONS\n")

                        val relevantPermissions =
                            selectedAppPermissions
                                .filter { permission ->
                                    permissionDescriptions.containsKey(
                                        permission.substringAfterLast('.')
                                    )
                                }
                                .distinct()

                        if (relevantPermissions.isEmpty()) {

                            append("No supported permissions found.\n")

                        } else {

                            relevantPermissions.forEach { permission ->

                                val shortName =
                                    permission.substringAfterLast('.')

                                val status =
                                    if (
                                        selectedAppGrantedPermissions.contains(
                                            permission
                                        )
                                    ) {
                                        "Granted"
                                    } else {
                                        "Not granted"
                                    }

                                append(
                                    "• $shortName — $status\n"
                                )
                            }
                        }

                        append("\n")
                    }

                    // AI SUMMARY
                    
                    // PERMISSION INTELLIGENCE

                    append("PERMISSION INTELLIGENCE\n\n")

                    if (
                        permissionIntelligence != null &&
                        permissionIntelligence.length() > 0
                    ) {

                        for (i in 0 until permissionIntelligence.length()) {

                            val item =
                                permissionIntelligence.getJSONObject(i)

                            append("Permission: ${item.optString("permission")}\n")

                            append(
                                "Description: ${item.optString("description")}\n"
                            )

                            append(
                                "Data Exposure: ${item.optString("data_exposure")}\n"
                            )

                            append(
                                "Sensitivity: ${item.optString("sensitivity")}\n"
                            )

                            append(
                                "Grant Status: ${item.optString("grant_status")}\n"
                            )

                            append(
                                "Purpose Relevance: ${item.optString("purpose_relevance")}\n\n"
                            )
                        }

                    } else {

                        append("Permission intelligence data unavailable.\n\n")
                    }

                    // AI SUMMARY

                    append("AI SECURITY SUMMARY\n")
                    append("$aiSummary\n\n")
                    // AI RECOMMENDATIONS

                    append("AI RECOMMENDATIONS\n")

                    if (recommendations != null) {

                        for (i in 0 until recommendations.length()) {

                            append(
                                "• ${recommendations.getString(i)}\n"
                            )
                        }
                    }

                    append("\n")

                    // RISK LEVEL

                    append("RISK LEVEL\n")
                    append("$level\n\n")

                    // RISK SCORE

                    append("RISK SCORE\n")
                    append("$score / 100\n\n")

                    // PERMISSIONS ANALYZED

                    append("PERMISSIONS ANALYZED\n")

                    for (i in 0 until permissions.length()) {

                        append(
                            "• ${permissions.getString(i)}\n"
                        )
                    }

                    // SECURITY FINDINGS

                    append("\nSECURITY FINDINGS\n\n")

                    for (i in 0 until findings.length()) {

                        val finding =
                            findings.getJSONObject(i)

                        append(
                            "• ${finding.optString("permission")}\n"
                        )

                        append(
                            "  Severity: ${finding.optString("severity")}\n"
                        )

                        append(
                            "  Reason: ${finding.optString("reason")}\n"
                        )

                        append(
                            "  Recommendation: ${finding.optString("recommendation")}\n\n"
                        )
                    }

                    // DISCLAIMER

                    append("DISCLAIMER\n")
                    append(disclaimerText)

                    if (appPackage != null) {

                        append(
                            "\n\nNote: This report analyzes declared permission information. " +
                            "It does not prove that the selected app is malicious or monitor its behavior."
                        )
                    }
                }

                // Update UI after successful analysis

                runOnUiThread {

                    resultView.text = result

                    resultBadge.text = level.uppercase()

                    resultBadge.setTextColor(
                        when (level.uppercase()) {
                            "HIGH" -> Color.rgb(255, 112, 130)
                            "MEDIUM" -> Color.rgb(255, 196, 92)
                            "LOW" -> Color.rgb(76, 222, 166)
                            else -> navy
                        }
                    )

                    resultBadge.background = roundedBackground(
                        when (level.uppercase()) {
                            "HIGH" -> Color.rgb(74, 34, 57)
                            "MEDIUM" -> Color.rgb(72, 57, 34)
                            "LOW" -> Color.rgb(25, 66, 60)
                            else -> backgroundColor
                        },
                        20
                    )

                    resultTitle.text =
                        if (appPackage != null) {
                            "App Security Report"
                        } else {
                            "Security Report"
                        }
                }

            } catch (e: Exception) {

                // Handle errors

                runOnUiThread {

                    resultBadge.text = "ERROR"

                    resultView.text =
                        "Analysis failed.\n\n" +
                        "${e.message ?: "Please try again."}\n\n" +
                        "Check your internet connection and try again."
                }

            } finally {

                connection?.disconnect()

                // Re-enable button

                runOnUiThread {

                    analyzeButton.isEnabled = true
                    analyzeButton.text = "ANALYZE SECURITY RISKS"
                }
            }

        }.start()
    }
}
