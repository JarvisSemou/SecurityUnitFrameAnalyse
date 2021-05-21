package org.semou.security_unit_frame_analyse

import androidx.compose.desktop.Window
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.selection.SelectionContainer
import androidx.compose.ui.unit.dp
import java.util.*


fun main() = Window(
    title = "SecurityUnit 2.0 FrameAnalyse ---- ShiYue Semou"
) {
    MaterialTheme {
        /** 输入的安全单元帧 */
        var securityUnitFrame by remember { mutableStateOf("") }

        /** 帧解析结果列表 */
        val resultList = remember { mutableStateListOf<HashMap<ResultType, String>>() }

        /** 是否显示原始帧，true 为显示，false 反之，默认为 true */
        var isShowOriginFrame by remember { mutableStateOf(true) }

        /** 是否显示含义详情，true 为显示，false 反之，默认为 false */
        var isShowMeaningDetails by remember { mutableStateOf(false) }

        var resultCode by remember {
            mutableStateOf<SecurityUnitFrameDecoder.SecurityUnitFrameDecodeResultCode>(
                SecurityUnitFrameDecoder.SecurityUnitFrameDecodeResultCode.DO_NOTHING
            )
        }
        //总体布局
        Column(
            modifier = Modifier.fillMaxSize().padding(
                start = 10.dp,
                end = 10.dp
            )
        ) {

            SelectionContainer {
                TextField(
                    value = securityUnitFrame,
                    modifier = Modifier.fillMaxWidth()
                        .padding(top = 10.dp)
                        .fillMaxHeight(0.15f),
                    label = { Text("输入安全单元帧") },
                    onValueChange = {
                        securityUnitFrame = it
                        if (it.isEmpty()) resultCode =
                            SecurityUnitFrameDecoder.SecurityUnitFrameDecodeResultCode.DO_NOTHING
                    })
            }
            Row(
                modifier = Modifier.fillMaxWidth()
                    .padding(top = 10.dp, end = 5.dp)
                    .wrapContentHeight(),
                horizontalArrangement = Arrangement.End
            ) {
                Button(
                    modifier = Modifier.width(100.dp),
                    onClick = {
                        resultCode = SecurityUnitFrameDecoder.decode(securityUnitFrame, resultList)
                    }
                ) {
                    Text("解   析")
                }
            }
            Column(
                modifier = Modifier.fillMaxSize()
                    .padding(bottom = 10.dp)
            ) {
                when (resultCode) {
                    is SecurityUnitFrameDecoder.SecurityUnitFrameDecodeResultCode.DONE -> {
                        // 帧显示列宽度比例
                        val frameDisplayWidth = 0.5f
                        // 意义显示列宽度比例
                        val meaningDisplayWidth = 0.5f

                        // 垂直滚动状态
                        val verticalScrollState = rememberScrollState(0f)
                        // 帧显示水平滚动状态
                        //val horizontalFrameScrollState = rememberScrollState(0f)
                        // 含义显示水平滚动状态
                        //val horizontalMeaningScrollState = rememberScrollState(0f)

                        CheckBoxPanel(
                            frameDisplayWidth,
                            meaningDisplayWidth,
                            isShowOriginFrame,
                            onFrameCheckboxChange = { isShowOriginFrame = it },
                            isShowMeaningDetails,
                            onMeaningCheckboxChange = { isShowMeaningDetails = it }
                        )

                        Column(
                            modifier = Modifier.fillMaxSize()
                                .verticalScroll(verticalScrollState)
                                .padding(
                                    start = 10.dp, end = 10.dp
                                )

                        ) {
                            // 奇数行背景色
                            val oddBackgroundColor = Color(177, 236, 235)
                            // 偶数行背景色
                            val evenBackgroundColor = Color(222, 255, 254)
                            // 鼠标悬浮高亮颜色
                            val highlightBackgroundColor = Color(238, 252, 217)
                            // 缓存颜色
                            val tmpColor by remember { mutableStateOf(Color(255, 255, 255)) }
                            //todo 鼠标悬浮高亮
                            var i = 1
                            var color: Color
                            for (result in resultList) {
                                color = when (i % 2 != 0) {
                                    true -> oddBackgroundColor
                                    false -> evenBackgroundColor
                                }
                                Row(
                                    modifier = Modifier.wrapContentHeight()
                                        .background(color)
                                        .fillMaxWidth()
                                ) {
                                    val subframe: String = if (isShowOriginFrame)
                                        result[ResultType.Origin]!!
                                    else
                                        result[ResultType.Analyzed]!!
                                    val meanings = if (isShowMeaningDetails)
                                        result[ResultType.MeaningDetails]!!
                                    else
                                        result[ResultType.Meaning]!!

                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth(frameDisplayWidth)
                                            .align(
                                                Alignment.CenterVertically
                                            )
                                            .heightIn(
                                                min = 25.dp
                                            )
                                            .padding(start = 5.dp)
                                    ) {
                                        Text(
                                            subframe,
                                            modifier=Modifier.padding(start=4.dp)
                                        )

                                    }
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .align(
                                                Alignment.CenterVertically
                                            )
                                            .heightIn(
                                                min = 25.dp
                                            )
                                            .padding(start = 5.dp)
                                    ) {
                                        Text(
                                            meanings,
                                            modifier=Modifier.padding(end=4.dp)
                                        )
                                    }
                                }
                                i++
                            }
                        }

                    }
                    else -> {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                resultCode.msg
                            )
                        }
                    }
                }
            }
        }

    }
}

/**
 * 状态切换栏
 */
@Suppress("FunctionName")
@Composable
fun CheckBoxPanel(
    frameDisplayWidth: Float,
    meaningDisplayWidth: Float,
    isShowOriginFrame: Boolean,
    onFrameCheckboxChange: (Boolean) -> Unit,
    isShowMeaningDetails: Boolean,
    onMeaningCheckboxChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth()
            .padding(start = 10.dp, end = 10.dp, top = 5.dp,bottom = 10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(frameDisplayWidth)
        ) {
            Checkbox(checked = isShowOriginFrame, onCheckedChange = onFrameCheckboxChange)
            Text("显示原始帧")
        }
        Row(
            modifier = Modifier.fillMaxWidth(meaningDisplayWidth)
        ) {
            Checkbox(checked = isShowMeaningDetails, onCheckedChange = onMeaningCheckboxChange)
            Text("显示字段详情")
        }
    }
}

/**
 * 结果列
 */
sealed class ResultType {
    /**
     * 原始列
     */
    object Origin : ResultType()

    /**
     * 解析后的列
     */
    object Analyzed : ResultType()

    /**
     * 简要解释列
     */
    object Meaning : ResultType()

    /**
     * 详细解释
     */
    object MeaningDetails : ResultType()
}