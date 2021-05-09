import androidx.compose.desktop.Window
import androidx.compose.foundation.layout.*
import androidx.compose.material.Button
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.TextField
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.selection.SelectionContainer
import androidx.compose.ui.unit.dp


fun main() = Window {
    MaterialTheme {
        var SecurityUnitFrame by remember { mutableStateOf("") }

        //todo 结果列表的数据结构有待完善，计划增加原始帧结构划分，帧数据解析，帧数据含义解释
        var resultList = remember { mutableStateListOf<String>() }

        var resultCode = remember {}
        //总体布局
        Column(
            modifier = Modifier.fillMaxSize()
        ) {

            SelectionContainer {
                TextField(
                    value = SecurityUnitFrame,
                    modifier = Modifier.fillMaxWidth()
                        .fillMaxHeight(0.15f),
                    label = { Text("输入安全单元帧") },
                    onValueChange = {
                        SecurityUnitFrame = it
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
                        SecurityUnitFrameDecoder.decode(SecurityUnitFrame, resultList)
                    }
                ) {
                    Text("解   析")
                }
            }
            Row(
                modifier = Modifier.fillMaxSize()
            ) {
                Column(
                    modifier = Modifier.fillMaxHeight()
                        .fillMaxWidth(0.3f)
                ) {
                    Text("原始结果")
                }
                Column(
                    modifier = Modifier.fillMaxHeight()
                        .fillMaxWidth(0.3f)
                ) {
                    Text("解析结果")
                }
                Column(
                    modifier = Modifier.fillMaxHeight()
                        .fillMaxWidth(0.4f)
                ) {
                    Text("含义解释")
                }
            }
        }

    }
}