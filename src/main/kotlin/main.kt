import androidx.compose.desktop.Window
import androidx.compose.foundation.layout.*
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.TextField
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.selection.SelectionContainer
import androidx.compose.ui.unit.dp


fun main() = Window {
    MaterialTheme {
        var securityUnitFrame by remember { mutableStateOf("") }

        val resultList = remember { mutableStateListOf<HashMap<ResultType, String>>() }

        var resultCode by remember {
            mutableStateOf<SecurityUnitFrameDecoder.SecurityUnitFrameDecodeResultCode>(
                SecurityUnitFrameDecoder.SecurityUnitFrameDecodeResultCode.DO_NOTHING
            )
        }
        //总体布局
        Column(
            modifier = Modifier.fillMaxSize()
        ) {

            SelectionContainer {
                TextField(
                    value = securityUnitFrame,
                    modifier = Modifier.fillMaxWidth()
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
            Row(
                modifier = Modifier.fillMaxSize()
            ) {
                //todo 待优化结果展示布局

                when (resultCode) {
                    is SecurityUnitFrameDecoder.SecurityUnitFrameDecodeResultCode.DONE -> {
                        Column(
                            modifier = Modifier.fillMaxHeight()
                                .fillMaxWidth(0.3f)
                        ) {
                            for (resultMap in resultList) Text(resultMap[ResultType.Origin]!!)
                        }
                        // todo 双击才显示分析结果
                        Column(
                            modifier = Modifier.fillMaxHeight()
                                .fillMaxWidth(0.3f)
                        ) {
                            for (resultMap in resultList) Text(resultMap[ResultType.Analyzed]!!)
                        }
                        Column(
//                            modifier = Modifier.fillMaxHeight()
//                                .fillMaxWidth(0.4f)
                            modifier = Modifier.fillMaxSize()
                        ) {
                            for (resultMap in resultList) Text(resultMap[ResultType.Meaning]!!)
                        }
                        // todo 增加点击显示含义详情
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