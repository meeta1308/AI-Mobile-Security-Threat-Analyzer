package com.example.mobilesecurityanalyzer

import android.app.Activity
import android.os.Bundle
import android.graphics.Typeface
import android.view.Gravity
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private val permissionChecks = mutableMapOf<String, CheckBox>()
    private lateinit var resultView: TextView

    private val permissionDescriptions = linkedMapOf(
        "CAMERA" to "Camera — photo/video capture",
        "RECORD_AUDIO" to "Microphone — audio recording",
        "ACCESS_FINE_LOCATION" to "Precise location",
        "READ_CONTACTS" to "Contacts access",
        "READ_SMS" to "SMS reading",
        "READ_CALL_LOG" to "Call history access",
        "READ_MEDIA_IMAGES" to "Photo/image access",
        "INTERNET" to "Internet access"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            setBackgroundColor(0xFFF6F8FC.toInt())
        }

        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val title = TextView(this).apply {
            text = "AI Mobile Security\nThreat Analyzer"
            textSize = 25f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFF172554.toInt())
        }
        content.addView(title)

        val intro = TextView(this).apply {
            text = "Select the permissions you want to assess. This prototype gives an initial indicator-based risk estimate."
            textSize = 15f
            setPadding(0, 12, 0, 18)
            setTextColor(0xFF334155.toInt())
        }
        content.addView(intro)

        permissionDescriptions.forEach { (permission, label) ->
            val checkBox = CheckBox(this).apply {
                text = label
                textSize = 15f
            }
            permissionChecks[permission] = checkBox
            content.addView(checkBox)
        }

        val analyzeButton = Button(this).apply {
            text = "Analyze Selected Permissions"
            setOnClickListener { analyzeSelection() }
        }
        content.addView(analyzeButton)

        resultView = TextView(this).apply {
            text = "Your analysis will appear here."
            textSize = 16f
            setTextColor(0xFF0F172A.toInt())
            setPadding(0, 20, 0, 20)
        }
        content.addView(resultView)

        val disclaimer = TextView(this).apply {
            text = "Note: A permission alone does not prove an app is malicious. This prototype does not scan other installed apps automatically."
            textSize = 12f
            setTextColor(0xFF64748B.toInt())
            setPadding(0, 12, 0, 12)
        }
        content.addView(disclaimer)

        scroll.addView(content)
        root.addView(scroll)
        setContentView(root)
    }

    private fun analyzeSelection() {
        val selected = permissionChecks.filterValues { it.isChecked }.keys.toList()
        if (selected.isEmpty()) {
            resultView.text = "Select at least one permission, then tap Analyze."
            return
        }

        val highRisk = setOf("READ_SMS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION", "RECORD_AUDIO")
        val mediumRisk = setOf("CAMERA", "READ_CONTACTS", "READ_MEDIA_IMAGES", "INTERNET")
        var score = 0
        val findings = mutableListOf<String>()

        selected.forEach { permission ->
            when (permission) {
                in highRisk -> {
                    score += 25
                    findings.add("• $permission: review why this access is needed.")
                }
                in mediumRisk -> {
                    score += 10
                    findings.add("• $permission: check whether this access matches the app's purpose.")
                }
            }
        }

        score = score.coerceAtMost(100)
        val level = when {
            score >= 60 -> "HIGH"
            score >= 30 -> "MEDIUM"
            else -> "LOW"
        }

        resultView.text = buildString {
            append("Risk indicator: $level\n")
            append("Score: $score / 100\n\n")
            append("Selected permissions:\n")
            selected.forEach { append("• $it\n") }
            append("\nFindings:\n")
            findings.forEach { append("$it\n") }
            append("\nThis is a simple demo heuristic, not a malware verdict.")
        }
    }
}
