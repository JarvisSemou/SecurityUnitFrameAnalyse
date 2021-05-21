@file:Suppress("LocalVariableName")

package org.semou.security_unit_frame_analyse

import java.nio.charset.Charset
import java.util.*
import kotlin.properties.Delegates

/**
 * 安全单元帧解析器
 *
 * @author Jarvis Semou
 */
class SecurityUnitFrameDecoder {

    @Suppress("FunctionName")
    companion object {
        /**
         * 解析安全单元帧
         *
         * @param frame 安全单元中帧
         * @param resultList 存放结果的列表
         */
        @ExperimentalUnsignedTypes
        fun decode(
            frame: String,
            resultList: MutableList<HashMap<ResultType, String>>
        ): SecurityUnitFrameDecodeResultCode {
            val decodeState: SecurityUnitFrameDecodeResultCode
            //字符串预处理----对数据域之外的部分去除空格、换行、转换为大写
            val pretreatmentFrame = frame.replace(Regex("[\\s\\n\\r]"), "").toUpperCase()
            //安全单元帧字节完整性检测
            if (!frameByteIntegrityCheck(pretreatmentFrame)) return SecurityUnitFrameDecodeResultCode.FRAME_BYTE_INCOMPLETE
            //安全单元帧格式完整性检测
            if (!frameFormatCheck(pretreatmentFrame)) return SecurityUnitFrameDecodeResultCode.FRAME_IMCOMPLETE
            //安全单元帧校验检测
            if (!frameCheck(pretreatmentFrame)) return SecurityUnitFrameDecodeResultCode.FRAME_CHECK_FAILED
            //安全单元帧解析
            decodeState = frameDecode(pretreatmentFrame, resultList)
            return decodeState
        }

        /**
         * 安全单元帧字节完整性检测
         * @param frame 安全单元中帧
         */
        private fun frameByteIntegrityCheck(frame: String): Boolean =
            frame.isNotEmpty() && frame.length % 2 == 0

        /**
         * 指示当前帧是否是 F=0xFE,C=0x03 的返回帧，如果是，则当前帧不包含 A。true 表示当前帧为返回帧，false 反之
         */
        private var isFE03Acknowledgement = false

        /**
         * 安全单元帧格式完整性检测
         * @param frame 安全单元帧
         * @return Boolean true 成功，false 失败
         */
        @Suppress("LocalVariableName")
        private fun frameFormatCheck(frame: String): Boolean {
            var decodeSuccess: Boolean

            // 字符串字符合法性判断
            val charList = listOf('1', '2', '3', "4", "5", "6", "7", "8", "9", "0", "A", "B", "C", "D", "E", "F")
            decodeSuccess = frame.filterNot { !charList.contains(it) }.isNotEmpty()
            if (!decodeSuccess) return decodeSuccess

            // 安全单元帧长度至少为 7，如果是返回帧，则长度至少为 8
            val receivedFrameByteLength = frame.length / 2  //实际接收的帧字节长度
            decodeSuccess = receivedFrameByteLength >= 8 || receivedFrameByteLength >= 7
            if (!decodeSuccess) {
                // 特殊情况：安全单元升级命令 F=0xFE, C=0x03 命令的返回帧无响应码（A），帧长度最短可达到 6 字节
                if (receivedFrameByteLength >= 6) {
                    val F = frame.substring(6, 8)
                    val A = frame.substring(8, 10).parseHexAsDecInt()
                    if (F == "FE" &&
                        A != 0x01 &&
                        A != 0x02 &&
                        A != 0x03 &&
                        A != 0x81 &&
                        A != 0x82
                    ) {
                        isFE03Acknowledgement = true
                        decodeSuccess = true
                    } else {
                        return decodeSuccess
                    }
                } else {
                    return decodeSuccess
                }
            }

            // 包含主要帧特征(注意 F=0xFE，C=0x03 的返回帧无响应码 A)
            // 发送标志：E9  LH  LL  F  C  DATA  CS E6
            // 接收标志：E9  LH  LL  F  A  S  DATA  CS E6

            // 以 E9 开头、以 E6 结尾
            decodeSuccess = frame.startsWith("E9") && frame.endsWith("E6")
            if (!decodeSuccess) return decodeSuccess

            // 帧长度符合 LH LL 要求（直接对比排除 E9 LH LL CS E6 等 5 个字节的帧标志之后的帧字节的数量）
            val LH = frame.substring(2, 4).parseHexAsDecInt() shl 8
            val LL = frame.substring(4, 6).parseHexAsDecInt()
            val frameLength = LH xor LL
            decodeSuccess = (receivedFrameByteLength - 5) == frameLength
            if (!decodeSuccess) return decodeSuccess

            // 主功能标识符有效
            val F = frame.substring(6, 8).parseHexAsDecInt()
            decodeSuccess = (F in 0x00..0x06) || F == 0xFE
            if (!decodeSuccess) return decodeSuccess

            // 命令码/响应码有效
            var C_or_A = frame.substring(8, 10).parseHexAsDecInt()
            C_or_A = C_or_A and 0x7f
            decodeSuccess = C_or_A in 0x00..0x0E
            if (!decodeSuccess) return decodeSuccess
            return decodeSuccess
        }

        /**
         * 安全单元帧校验检测
         * @param frame 安全单元帧
         * @return Boolean true 成功，false 失败
         */
        private fun frameCheck(frame: String): Boolean {
            val decodeSuccess: Boolean
            // 帧校验有效
            val checkAtFrame = frame.substring(frame.length - 4, frame.length - 2).parseHexAsDecInt()
            var realCheck = 0x00
            val loopEnd = frame.length - 6
            for (i in 0..loopEnd step 2) {
                realCheck += frame.substring(i, i + 2).parseHexAsDecInt()
                realCheck = realCheck and 0xff
            }
            decodeSuccess = realCheck == checkAtFrame
            return decodeSuccess
        }

        // 主要帧特征
        // 发送标志：E9  LH  LL  F  C  DATA  CS E6
        // 接收标志：E9  LH  LL  F  A  S  DATA  CS E6
        private const val E9 = "E9"
        private const val E6 = "E6"
        private lateinit var CS: String
        private var LH by Delegates.notNull<Int>()
        private var LL by Delegates.notNull<Int>()

        /** 从原始帧中解析出来的帧字节长度，包含 F、C 或 A、S、DATA */
        private var frameByteLength by Delegates.notNull<Int>()

        /** DATA（数据域）的字节长度 */
        private var dataDomainByteLength by Delegates.notNull<Int>()

        /** DATA（数据域）在 frame 字符串中的字符长度 */
        private var dataDomainCharLength by Delegates.notNull<Int>()

        /** DATA（数据域）在 frame 字符串中的起始字符索引编号 */
        private var dataDomainCharStartIndex by Delegates.notNull<Int>()

        /** DATA（数据域）在 frame 字符串中的字符结束索引编号 */
        private var dataDomainCharEndIndex by Delegates.notNull<Int>()
        private var F by Delegates.notNull<Int>()
        private var C_or_A by Delegates.notNull<Int>()
        private var C by Delegates.notNull<Int>()
        private var A by Delegates.notNull<Int>()
        private var F_C_or_A by Delegates.notNull<Int>()

        /** 指示当前帧是否为返回帧，true 表示当前帧为返回帧，false 反之 */
        private var isAcknoledgement by Delegates.notNull<Boolean>()
        private var S by Delegates.notNull<Int>()

        /**
         * 安全单元帧解析
         * @param frame 安全单元帧
         * @param resultList 解析结果列表
         * @return SecurityUnitFrameDecodeResultCode @link{SecurityUnitFrameDecodeResultCode}
         */
        @ExperimentalUnsignedTypes
        @Suppress("LocalVariableName")
        private fun frameDecode(
            frame: String,
            resultList: MutableList<HashMap<ResultType, String>>
        ): SecurityUnitFrameDecodeResultCode {
            val decodeResultCode = SecurityUnitFrameDecodeResultCode.DONE
            resultList.clear()

            //获取初始信息
            CS = frame.substring(frame.length - 4, frame.length - 2)
            LH = frame.substring(2, 4).parseHexAsDecInt() shl 8
            LL = frame.substring(4, 6).parseHexAsDecInt()
            frameByteLength = LH xor LL
            F = frame.substring(6, 8).parseHexAsDecInt()
            C_or_A = frame.substring(8, 10).parseHexAsDecInt()
            C = C_or_A and 0x7F
            A = C_or_A or 0x80
            F_C_or_A = (F shl 8) xor C_or_A
            isAcknoledgement = C_or_A and 0x80 == 0x80
            if (isAcknoledgement) {
                S = frame.substring(10, 12).parseHexAsDecInt()
                dataDomainByteLength = frameByteLength - 3
                dataDomainCharStartIndex = 12
            } else {
                dataDomainByteLength = frameByteLength - 2
                dataDomainCharStartIndex = 10
            }
            // 对 F=0xFE,C=0x03 的返回帧的数据域长度的特殊计算
            if (isFE03Acknowledgement) {
                dataDomainByteLength = frameByteLength - 1
                dataDomainCharStartIndex = 8
            }
            dataDomainCharLength = dataDomainByteLength * 2
            dataDomainCharEndIndex = dataDomainCharStartIndex + dataDomainCharLength

            // 填充 E9 LH LL F C A S
            val map_E9 = HashMap<ResultType, String>()
            val map_LHLL = HashMap<ResultType, String>()
            val map_F = HashMap<ResultType, String>()
            val map_C_or_A = HashMap<ResultType, String>()
            val map_S = HashMap<ResultType, String>()
            map_E9[ResultType.Origin] = E9
            map_E9[ResultType.Analyzed] = E9
            map_E9[ResultType.Meaning] = "帧起始码"
            map_E9[ResultType.MeaningDetails] = "标识一桢信息的开始"
            map_LHLL[ResultType.Origin] = frameByteLength.toZeroPrefixHexString(2)
            map_LHLL[ResultType.Analyzed] = frameByteLength.toString()
            map_LHLL[ResultType.Meaning] = "帧长度"
            map_LHLL[ResultType.MeaningDetails] = "标识从主功能标识开始到数据域最后1字节结束的字节数。2字节16进制数，高字节在前，低字节在后"
            map_F[ResultType.Origin] = F.toZeroPrefixHexString()
            map_F[ResultType.Analyzed] = F.toString()
            map_F[ResultType.Meaning] = F.get_F_Meaning()
            map_F[ResultType.MeaningDetails] = "表示主命令类型"
            if (!isFE03Acknowledgement) {
                map_C_or_A[ResultType.Origin] = C_or_A.toZeroPrefixHexString()
                map_C_or_A[ResultType.Analyzed] = C_or_A.toString()
                map_C_or_A[ResultType.Meaning] = C_or_A.get_C_or_A_Meaning(F)
                val C_or_A_MeaningDetails = C_or_A.get_C_or_A_MeaningDetails(F)
                map_C_or_A[ResultType.MeaningDetails] = """
                    标识命令类型，最高位D7=0，D6-D0 命令码。
                    命令解释详情：$C_or_A_MeaningDetails
                """.trimIndent()
                if (isAcknoledgement) {
                    map_S[ResultType.Origin] = S.toZeroPrefixHexString()
                    map_S[ResultType.Analyzed] = S.toString()
                    map_S[ResultType.Meaning] = S.get_S_Meaning(F, A)
                    map_C_or_A[ResultType.MeaningDetails] = "标识响应类型，最高位 D7=1，D6-D0 响应码与命令码相同"
                    map_S[ResultType.MeaningDetails] = "标识响应状态，仅适用于响应帧，00 表示正常响应，非 00 为异常响应"
                }
            }
            resultList.addResults(
                map_E9,
                map_LHLL,
                map_F
            )
            if (!isFE03Acknowledgement) {
                resultList.add(map_C_or_A)
                if (isAcknoledgement) resultList.add(map_S)
            }
            // 解析数据域
            if (dataDomainByteLength != 0) parseFrameData(frame, resultList)

            // 填充 CS E6
            val map_CS = HashMap<ResultType, String>()
            val map_E6 = HashMap<ResultType, String>()
            map_CS[ResultType.Origin] = CS.toZeroPrefixHexString()
            map_CS[ResultType.Analyzed] = CS.parseHexAsDecString()
            map_CS[ResultType.Meaning] = "帧校验"
            map_CS[ResultType.MeaningDetails] = "帧起始码到数据域最后一个字节的算术和（模256）"
            map_E6[ResultType.Origin] = E6
            map_E6[ResultType.Analyzed] = E6
            map_E6[ResultType.Meaning] = "帧结束码"
            map_E6[ResultType.MeaningDetails] = "标识一桢信息的结束"
            resultList.addResults(
                map_CS,
                map_E6
            )

            return decodeResultCode
        }

        /**
         * 解析帧数据域
         *
         * @param frame 帧
         * @param resultList 存放结果的列表
         */
        @ExperimentalUnsignedTypes
        private fun parseFrameData(
            frame: String,
            resultList: MutableList<HashMap<ResultType, String>>
        ) {
            // 特殊情况：安全单元升级命令 F=0xFE, C=0x03 命令的返回帧无响应码（A），只能单独处理帧数据域解析
            if (isFE03Acknowledgement) {
                //todo 解析 FE03 返回帧的数据域
                return
            }
            when (F_C_or_A) {
                //todo 待完成数据域解析
                // 注释的方法皆无数据域
//                0x0001 -> parse_0001_DataDomain(frame,resultList)
                0x0002 -> parse_0002_DataDomain(frame, resultList)
                0x0003 -> parse_0003_DataDomain(frame, resultList)
                0x0004 -> parse_0004_DataDomain(frame, resultList)
                0x0005 -> parse_0005_DataDomain(frame, resultList)
                0x0006 -> parse_0006_DataDomain(frame, resultList)
                0x0007 -> parse_0007_DataDomain(frame, resultList)
                0x0008 -> parse_0008_DataDomain(frame, resultList)
                0x0009 -> parse_0009_DataDomain(frame, resultList)
                0x000A -> parse_000A_DataDomain(frame, resultList)
                0x0081 -> parse_0081_DataDomain(frame, resultList)
//                0x0082->parse_0082_DataDomain(frame,resultList)
//                0x0083->parse_0083_DataDomain(frame,resultList)
//                0x0084->parse_0084_DataDomain(frame,resultList)
//                0x0085->parse_0085_DataDomain(frame,resultList)
                0x0086 -> parse_0086_DataDomain(frame, resultList)
                0x0087 -> parse_0087_DataDomain(frame, resultList)
//                0x0088->parse_0088_DataDomain(frame,resultList)
                0x0089 -> parse_0089_DataDomain(frame, resultList)
                0x008A -> parse_008A_DataDomain(frame, resultList)
//                // 现场服务终端与管理系统交互类命令
                0x0101 -> parse_0101_DataDomain(frame, resultList)
                0x0102 -> parse_0102_DataDomain(frame, resultList)
                0x0103 -> parse_0103_DataDomain(frame, resultList)
                0x0104 -> parse_0104_DataDomain(frame, resultList)
                0x0105 -> parse_0105_DataDomain(frame, resultList)
                0x0106 -> parse_0106_DataDomain(frame, resultList)
                0x0107 -> parse_0107_DataDomain(frame, resultList)
                0x0108 -> parse_0108_DataDomain(frame, resultList)
                0x0109 -> parse_0109_DataDomain(frame, resultList)
                0x010A -> parse_010A_DataDomain(frame, resultList)
                0x0181 -> parse_0181_DataDomain(frame, resultList)
                0x0182 -> parse_0182_DataDomain(frame, resultList)
                0x0183 -> parse_0183_DataDomain(frame, resultList)
                0x0184 -> parse_0184_DataDomain(frame, resultList)
                0x0185 -> parse_0185_DataDomain(frame, resultList)
//                0x0186->parse_0186_DataDomain(frame,resultList)
                0x0187 -> parse_0187_DataDomain(frame, resultList)
//                0x0188->parse_0188_DataDomain(frame,resultList)
                0x0189 -> parse_0189_DataDomain(frame, resultList)
//                0x018A->parse_018A_DataDomain(frame,resultList)
//                // 现场服务终端与电能表的交互命令
                0x0201 -> parse_0201_DataDomain(frame, resultList)
                0x0202 -> parse_0202_DataDomain(frame, resultList)
                0x0203 -> parse_0203_DataDomain(frame, resultList)
                0x0204 -> parse_0204_DataDomain(frame, resultList)
                0x0205 -> parse_0205_DataDomain(frame, resultList)
                0x0206 -> parse_0206_DataDomain(frame, resultList)
                0x0207 -> parse_0207_DataDomain(frame, resultList)
                0x0208 -> parse_0208_DataDomain(frame, resultList)
                0x0209 -> parse_0209_DataDomain(frame, resultList)
                0x020A -> parse_020A_DataDomain(frame, resultList)
                0x020B -> parse_020B_DataDomain(frame, resultList)
                0x020C -> parse_020C_DataDomain(frame, resultList)
                0x020D -> parse_020D_DataDomain(frame, resultList)
                0x020E -> parse_020E_DataDomain(frame, resultList)
                0x0281 -> parse_0281_DataDomain(frame, resultList)
                0x0282 -> parse_0282_DataDomain(frame, resultList)
                0x0283 -> parse_0283_DataDomain(frame, resultList)
                0x0284 -> parse_0284_DataDomain(frame, resultList)
                0x0285 -> parse_0285_DataDomain(frame, resultList)
                0x0286 -> parse_0286_DataDomain(frame, resultList)
                0x0287 -> parse_0287_DataDomain(frame, resultList)
                0x0288 -> parse_0288_DataDomain(frame, resultList)
                0x0289 -> parse_0289_DataDomain(frame, resultList)
//                0x028A->parse_028A_DataDomain(frame,resultList)
                0x028B -> parse_028B_DataDomain(frame, resultList)
                0x028C -> parse_028C_DataDomain(frame, resultList)
                0x028D -> parse_028D_DataDomain(frame, resultList)
//                0x028E->parse_028E_DataDomain(frame,resultList)
//                // 现场服务终端与安全隔离网关交互类命令
                0x0301 -> parse_0301_DataDomain(frame, resultList)
                0x0302 -> parse_0302_DataDomain(frame, resultList)
                0x0303 -> parse_0303_DataDomain(frame, resultList)
                0x0304 -> parse_0304_DataDomain(frame, resultList)
                0x0305->parse_0305_DataDomain(frame,resultList)
                0x0381->parse_0381_DataDomain(frame,resultList)
                0x0382->parse_0382_DataDomain(frame,resultList)
                0x0383->parse_0383_DataDomain(frame,resultList)
                0x0384->parse_0384_DataDomain(frame,resultList)
//                0x0385->parse_0385_DataDomain(frame,resultList)
//                // 现场服务终端与电子封印的交互命令
//                0x0401->parse_0401_DataDomain(frame,resultList)
//                0x0402->parse_0402_DataDomain(frame,resultList)
//                0x0403->parse_0403_DataDomain(frame,resultList)
//                0x0404->parse_0404_DataDomain(frame,resultList)
//                0x0405->parse_0405_DataDomain(frame,resultList)
//                0x0406->parse_0406_DataDomain(frame,resultList)
//                0x0407->parse_0407_DataDomain(frame,resultList)
//                0x0408->parse_0408_DataDomain(frame,resultList)
//                0x0409->parse_0409_DataDomain(frame,resultList)
//                0x040A->parse_040A_DataDomain(frame,resultList)
//                0x0481->parse_0481_DataDomain(frame,resultList)
//                0x0482->parse_0482_DataDomain(frame,resultList)
//                0x0483->parse_0483_DataDomain(frame,resultList)
//                0x0484->parse_0484_DataDomain(frame,resultList)
//                0x0485->parse_0485_DataDomain(frame,resultList)
//                0x0486->parse_0486_DataDomain(frame,resultList)
//                0x0487->parse_0487_DataDomain(frame,resultList)
//                0x0488->parse_0488_DataDomain(frame,resultList)
//                0x0489->parse_0489_DataDomain(frame,resultList)
//                0x048A->parse_048A_DataDomain(frame,resultList)
//                // 现场服务终端与电子标签的交互命令
//                0x0501->parse_0501_DataDomain(frame,resultList)
//                0x0502->parse_0502_DataDomain(frame,resultList)
//                0x0503->parse_0503_DataDomain(frame,resultList)
//                0x0504->parse_0504_DataDomain(frame,resultList)
//                0x0581->parse_0581_DataDomain(frame,resultList)
//                0x0582->parse_0582_DataDomain(frame,resultList)
//                0x0583->parse_0583_DataDomain(frame,resultList)
//                0x0584->parse_0584_DataDomain(frame,resultList)
//                // 现场服务终端与外设交互命令
//                0x0601->parse_0601_DataDomain(frame,resultList)
//                0x0602->parse_0602_DataDomain(frame,resultList)
//                0x0603->parse_0603_DataDomain(frame,resultList)
//                0x0604->parse_0604_DataDomain(frame,resultList)
//                0x0605->parse_0605_DataDomain(frame,resultList)
//                0x0606->parse_0606_DataDomain(frame,resultList)
//                0x0681->parse_0681_DataDomain(frame,resultList)
//                0x0682->parse_0682_DataDomain(frame,resultList)
//                0x0683->parse_0683_DataDomain(frame,resultList)
//                0x0684->parse_0684_DataDomain(frame,resultList)
//                0x0685->parse_0685_DataDomain(frame,resultList)
//                0x0686->parse_0686_DataDomain(frame,resultList)
//                // 安全单元升级命令
//                0xFE01->parse_FE01_DataDomain(frame,resultList)
//                0xFE02->parse_FE02_DataDomain(frame,resultList)
//                0xFE03->parse_FE03_DataDomain(frame,resultList)
//                0xFE04->parse_FE04_DataDomain(frame,resultList)
//                0xFE81->parse_FE81_DataDomain(frame,resultList)
//                0xFE82->parse_FE82_DataDomain(frame,resultList)
//                0xFE84->parse_FE84_DataDomain(frame,resultList)
            }
        }

        private fun parse_0384_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "返回数据 MAC")
            
            val data_1_byteLength=4
            
            val data_1=frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
            
            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )
            
            resultList.add(map_1)
        }

        private fun parse_0383_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "返回数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "返回数据内容")

            val data_1_byteLength = 2
            val data_2_byteLength = UNCERTAIN_LENGTH

            val (data_1, data_2) = frame
                .substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
                .parse_2_N_HexData()

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.append(
                data_2_byteLength,
                ResultType.Origin to """
                    $data_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_2
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    明文数据
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0382_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "返回数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "返回数据内容")

            val data_1_byteLength = 2
            val data_2_byteLength = UNCERTAIN_LENGTH

            val (data_1, data_2) = frame
                .substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
                .parse_2_N_HexData()

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.append(
                data_2_byteLength,
                ResultType.Origin to """
                    $data_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_2
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    应用数据单元（密文 + MAC）
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0381_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密文 M2")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "M2 签名")
            
            val data_1_byteLength=48
            val data_2_byteLength=64
            
            val data_2_offset= dataDomainCharStartIndex+data_1_byteLength*2
            
            val data_1=frame.substring(dataDomainCharStartIndex,data_2_offset)
            val data_2=frame.substring(data_2_offset, dataDomainCharEndIndex)
            
            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )
            
            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ){
                _,_,_,_,_,preDes->
                preDes+"""
                    签名内容
                """.trimIndent()
            }
            
            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0305_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            parse_0304_DataDomain(frame,resultList)
        }

        private fun parse_0304_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥 ID")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据长度")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据内容")

            val data_1_byteLength = 1
            val data_2_byteLength = 2
            val data_3_byteLength = UNCERTAIN_LENGTH

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, dataDomainCharEndIndex)

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            map_2.append(
                data_2_byteLength,
                ResultType.Origin to """
                    $data_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_2
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    应用数据单元长度
                """.trimIndent()
            }

            map_3.append(
                data_3_byteLength,
                ResultType.Origin to """
                        $data_3
                    """.trimIndent(),
                ResultType.Analyzed to """
                    $data_3
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    应用数据单元
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3
            )
        }

        private fun parse_0303_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据内容")

            val data_1_byteLength = 2
            val data_2_byteLength = UNCERTAIN_LENGTH

            val (data_1, data_2) = frame
                .substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
                .parse_2_N_HexData()

            map_1.append(
                data_1_byteLength,
                ResultType.Origin to """
                    $data_1
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_1
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    应用数据单元长度
                """.trimIndent()
            }

            map_2.append(
                data_2_byteLength,
                ResultType.Origin to """
                    $data_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_2
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    应用数据单元（密文 + MAC）
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0302_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据内容")

            val data_1_byteLength = 2
            val data_2_byteLength = UNCERTAIN_LENGTH

            val (data_1, data_2) = frame
                .substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
                .parse_2_N_HexData()

            map_1.append(
                data_1_byteLength,
                ResultType.Origin to """
                    $data_1
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_1
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    应用数据单元长度
                """.trimIndent()
            }

            map_2.append(
                data_2_byteLength,
                ResultType.Origin to """
                    $data_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_2
                """.trimIndent()
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    应用数据单元（数据明文）
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0301_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密文 M1")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "M1 签名")

            val data_1_byteLength = 32
            val data_2_byteLength = 64

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_028D_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            // 028D 和 028C 解析方式相同
            parse_028C_DataDomain(frame, resultList)
        }

        private fun parse_028C_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据明文长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据明文")

            val data_1_byteLength = 2
            val data_2_byteLength = dataDomainByteLength - data_1_byteLength

            val (data_1, data_2) =
                frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
                    .parse_2_N_HexData()

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_028B_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据")

            val data_1_byteLength = 2
            val data_2_byteLength = dataDomainByteLength - data_1_byteLength

            val (data_1, data_2) =
                frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
                    .parse_2_N_HexData()

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }


        private fun parse_0289_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "会话数据")

            val data_1_byteLength = 36

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            val data_1_1_byteLength = 32
            //val data_1_2_byteLength=4

            val data_1_2_offset = 0 + data_1_1_byteLength * 2

            val data_1_1 = data_1.substring(0, data_1_2_offset)
            val data_1_2 = data_1.substring(data_1_2_offset)

            map_1.append(
                data_1_byteLength,
                origin {
                    """
                        $data_1_1
                        $data_1_2
                    """
                },
                analyzed {
                    """
                        $data_1_1
                        $data_1_2
                    """
                }
            )

            resultList.add(map_1)
        }

        private fun parse_0288_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "充值金额")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "购电次数")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "客户编号")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")

            val data_1_byteLength = 4
            val data_2_byteLength = 4
            val data_3_byteLength = 4
            val data_4_byteLength = 6
            val data_5_byteLength = 4

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parsePlainHexData(
                data_4,
                data_4_byteLength
            )

            map_5.parsePlainHexData(
                data_5,
                data_5_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5
            )
        }

        private fun parse_0287_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥数据块")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")

            val data_1_byteLength = dataDomainByteLength - 4
            val data_2_byteLength = 4

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            val (data_1_1, data_1_2) = data_1.parse_2_N_HexData()

            map_1.append(
                data_1_byteLength,
                ResultType.Origin to """
                    $data_1_1
                    $data_1_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    密钥数据块长度：${data_1_1.parseHexAsDecInt()}
                    密钥 1 ... 密钥 N：
                    $data_1_2
                """.trimIndent(),
            ) { _, dataMeaningDes, _, dataFormatDes, meaningDetailsDes, _ ->
                """
                    $dataMeaningDes
                    ${DATA_COUNT}2 + N
                    $dataFormatDes
                    $meaningDetailsDes
                    数据长度（2B）+ 密钥1 ... 密钥 N
                """.trimIndent()
            }

//            map_1 += hashMapOf(
//                org.semou.SecurityUnitFrameAnalyse.ResultType.Origin to """
//                    $data_1_1
//                    $data_1_2
//                """.trimIndent(),
//                org.semou.SecurityUnitFrameAnalyse.ResultType.Analyzed to """
//                    密钥数据块长度：${data_1_1.parseHexAsDecInt()}
//                    密钥 1 ... 密钥 N：
//                    $data_1_2
//                """.trimIndent(),
//                org.semou.SecurityUnitFrameAnalyse.ResultType.MeaningDetails to """
//                    $DATA_NAME${map_1[org.semou.SecurityUnitFrameAnalyse.ResultType.Meaning]}
//                    ${DATA_COUNT}2 + N
//                    $DATA_FORMAT_HEX
//                    $DATA_MEANING_DETAILS
//                    数据长度（2B）+ 密钥1 ... 密钥 N
//                """.trimIndent()
//            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0286_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "校时数据密文")

            val data_1_byteLength = 2
            val data_2_byteLength = 32 * 6 + 48

            val (data_1, data_2) = frame.parse_2_N_HexData()

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    数据长度
                """.trimIndent()
            }

            val data_2_1 = data_2.substring(0, data_2.length - 96)
            val data_2_2 = data_2.substring(data_2.length - 96)
            val meterKeyCharLength = 64
            val data_2_1_origin = StringBuffer()
            val data_2_1_analyzed = StringBuffer()
            var key: String
            var keyNum = 1
            for (i in data_2_1.indices step meterKeyCharLength) {
                key = data_2_1.substring(i, i + meterKeyCharLength) + "\n|"
                data_2_1_origin.append(key)
                data_2_1_analyzed.append("密钥 ${keyNum}：$key")
                keyNum++
            }
            map_2 += hashMapOf(
                ResultType.Origin to """
                    |$data_2_1_origin
                    |$data_2_2
                """.trimMargin(),
                ResultType.Analyzed to """
                    |$data_2_1_analyzed
                    |$data_2_2
                """.trimMargin(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.MeaningDetails]}
                    ${DATA_COUNT}32 * 6 + 48  (240)
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0285_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "校时数据密文")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")

            val data_1_byteLength = 2
            val data_3_byteLength = 4
            val data_2_byteLength = dataDomainByteLength - (data_1_byteLength + data_3_byteLength)

            val (data_1, data_2) = frame.parse_2_N_HexData()
            val data_3 = frame.substring(dataDomainCharEndIndex - 8)

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    注：包含 MAC 长度
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3
            )
        }

        private fun parse_0284_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "参数明文或密文")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")

            val data_1_byteLength = 2
            val data_3_byteLength = 4
            val data_2_byteLength = dataDomainByteLength - (data_1_byteLength + data_3_byteLength)

            val (data_1, data_2) = frame.parse_2_N_HexData()
            val data_3 = frame.substring(dataDomainCharEndIndex - 8)

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    注：包含 MAC 长度
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3
            )
        }

        private fun parse_0283_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "控制数据密文")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")

            val data_1_byteLength = 16
            val data_2_byteLength = 4

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0282_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "身份认证密文")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数 1")

            val data_1_byteLength = 8
            val data_2_byteLength = 8

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0281_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数 2 密文")

            val data_1_byteLength = 8

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            resultList.addResults(map_1)
        }

        private fun parse_020E_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号/ESAM 序列号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "OAD")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据长度")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据")

            val data_1_byteLength = 8
            val data_2_byteLength = 4
            val data_3_byteLength = 2
            val data_4_byteLength = dataDomainByteLength - (data_1_byteLength + data_2_byteLength + data_3_byteLength)

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_3_offset)
            val data_4 = frame.substring(data_4_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补 0x00；
                    公钥状态下当前值为 ESAM 序列号，私钥状态下为表号
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parseDecHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parsePlainHexData(
                data_4,
                data_4_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4
            )
        }

        private fun parse_020D_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "分散因子")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据明文长度")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "应用层数据明文")

            val data_1_byteLength = 8
            val data_2_byteLength = 2
            val data_3_byteLength = dataDomainByteLength - (data_1_byteLength + data_2_byteLength)

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parseDecHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3
            )
        }

        private fun parse_020C_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "链路用户数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "链路用户数据")

            val data_1_byteLength = 2

            val (data_1, data_2) = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex).parse_2_N_HexData()

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            val data_2_1_byteLength = 1
            val data_2_2_byteLength = 1
            val data_2_3_byteLength = 2
            val data_2_5_byteLength = 1
            val data_2_6_byteLength = 1
            val data_2_7_byteLength = 4
            val data_2_4_byteLength =
                dataDomainByteLength - (data_1_byteLength + data_2_1_byteLength + data_2_2_byteLength +
                        data_2_3_byteLength + data_2_5_byteLength + data_2_6_byteLength + data_2_7_byteLength)

            val data_2_2_offset = 0 + data_2_1_byteLength * 2
            val data_2_3_offset = data_2_2_offset + data_2_2_byteLength * 2
            val data_2_4_offset = data_2_3_offset + data_2_3_byteLength * 2
            val data_2_5_offset = data_2_4_offset + data_2_4_byteLength * 2
            val data_2_6_offset = data_2_5_offset + data_2_5_byteLength * 2
            val data_2_7_offset = data_2_6_offset + data_2_6_byteLength * 2

            val data_2_1 = data_2.substring(0, data_2_2_offset)
            val data_2_2 = data_2.substring(data_2_2_offset, data_2_3_offset)
            val data_2_3 = data_2.substring(data_2_3_offset, data_2_4_offset)
            val data_2_4 = data_2.substring(data_2_4_offset, data_2_5_offset)
            val data_2_5 = data_2.substring(data_2_5_offset, data_2_6_offset)
            val data_2_6 = data_2.substring(data_2_6_offset, data_2_7_offset)
            val data_2_7 = data_2.substring(data_2_7_offset)

            map_2 += hashMapOf(
                ResultType.Origin to """
                    $data_2_1
                    $data_2_2
                    $data_2_3
                    $data_2_4
                    $data_2_5
                    $data_2_6
                    $data_2_7
                """.trimIndent(),
                ResultType.Analyzed to """
                    $data_2_1
                    数据型式：${
                    when (data_2_2) {
                        "00" -> "明文"
                        "01" -> "密文"
                        else -> "未知数据形式"
                    }
                }
                    数据长度：${data_2_3.parseHexAsDecInt()}
                    数据内容：${data_2_4}
                    是否含数据验证消息：${
                    when (data_2_5) {
                        "00" -> "不含 MAC"
                        "01" -> "含有 MAC"
                        else -> "未知"
                    }
                }
                    数据验证消息：${data_2_6}
                    MAC：${data_2_7}
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    ${DATA_COUNT}N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    0x90
                    数据形式（1B）：
                        00：明文
                        01：密文
                    数据长度（2B，大字节序）
                    数据内容（N）
                    是否含数据验证消息（1B）：
                        00：不含 MAC
                        01：含有 MAC
                    数据验证消息（1B）
                    MAC（4B）
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )

        }

        private fun parse_020B_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "主站任务数据")

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            val data_1_1_byteLength = 1
            val data_1_2_byteLength = 1
            val data_1_3_byteLength = 2
            val data_1_5_byteLength = 4
            val data_1_4_byteLength =
                dataDomainByteLength - (data_1_1_byteLength + data_1_2_byteLength + data_1_3_byteLength + data_1_5_byteLength)

            val data_1_2_offset = 0 + data_1_1_byteLength * 2
            val data_1_3_offset = data_1_2_offset + data_1_2_byteLength * 2
            val data_1_4_offset = data_1_3_offset + data_1_3_byteLength * 2
            val data_1_5_offset = data_1_4_offset + data_1_4_byteLength * 2

            val data_1_1 = data_1.substring(0, data_1_2_offset)
            val data_1_2 = data_1.substring(data_1_2_offset, data_1_3_offset)
            val data_1_3 = data_1.substring(data_1_3_offset, data_1_4_offset)
            val data_1_4 = data_1.substring(data_1_4_offset, data_1_5_offset)
            val data_1_5 = data_1.substring(data_1_5_offset)

            map_1 += hashMapOf(
                ResultType.Origin to """
                    ${data_1_1.toZeroPrefixHexString(data_1_1_byteLength)}
                    ${data_1_2.toZeroPrefixHexString(data_1_2_byteLength)}
                    ${data_1_3.toZeroPrefixHexString(data_1_3_byteLength)}
                    ${data_1_4.toZeroPrefixHexString(data_1_4_byteLength)}
                    ${data_1_5.toZeroPrefixHexString(data_1_5_byteLength)}
                """.trimIndent(),
                ResultType.Analyzed to """
                    安全模式字：${
                    when (data_1_1) {
                        "00" -> "明文"
                        "01" -> "明文 + MAC"
                        "03" -> "密文 + MAC"
                        "04" -> "明文 + RN 随机数"
                        else -> "未知安全模式字"
                    }
                }
                    任务参数类型：${data_1_2.toZeroPrefixHexString(data_1_2_byteLength)}
                    应用层数据长度：${data_1_3.parseHexAsDecInt()}
                    应用层数据：${data_1_4.toZeroPrefixHexString(data_1_4_byteLength)}
                    MAC：${data_1_5.toZeroPrefixHexString(data_1_5_byteLength)}
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_1[ResultType.Meaning]}
                    ${DATA_COUNT}N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    安全模式字 （1B）
                    任务参数类型 （1B）
                    应用层数据长度 （2B）
                    应用层数据 （N）
                    MAC （4B，也称保护码）
                """.trimIndent()
            )
            resultList.add(map_1)
        }

        private fun parse_020A_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥包")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号 / ESAM 序列号")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥标识")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "会话数据")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")

            val data_1_byteLength = 48 * 4
            val data_2_byteLength = 8
            val data_3_byteLength = 16
            val data_4_byteLength = 48 + 4
            val data_5_byteLength = 7

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    若为公钥：使用ESAM序列号
                    若为私钥：用表号高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parsePlainHexData(
                data_4,
                data_4_byteLength
            )

            map_5.parseDateHexData(
                data_5,
                data_5_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5
            )
        }

        private fun parse_0209_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥包")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号 / ESAM 序列号")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "会话计数器")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")

            val data_1_byteLength = 48 * 4
            val data_2_byteLength = 8
            val data_3_byteLength = 4
            val data_4_byteLength = 7

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    若为公钥：使用ESAM序列号
                    若为私钥：用表号高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_3.parseDecHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parseDateHexData(
                data_4,
                data_4_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4
            )
        }

        private fun parse_0208_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "权限数据 1")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "权限数据 2")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "开户数据")
            val map_6 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")

            val data_1_byteLength = 8
            val data_2_byteLength = 4
            val data_3_byteLength = 48
            val data_4_byteLength = 48
            val data_5_byteLength = 26
            val data_6_byteLength = 7

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2
            val data_6_offset = data_5_offset + data_5_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, data_5_byteLength)
            val data_6 = frame.substring(data_6_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    身份认证产生的随机数
                """.trimIndent()
            }

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parsePlainHexData(
                data_4,
                data_4_byteLength
            )

            val data_5_1_charLength = 8
            val data_5_2_charLength = 8
            val data_5_3_charLength = 8
            val data_5_4_charLength = 8
            val data_5_5_charLength = 12
            //val data_5_6_charLength=8
            val data_5_2_charOffset = 0 + data_5_1_charLength
            val data_5_3_charOffset = data_5_2_charOffset + data_5_2_charLength
            val data_5_4_charOffset = data_5_3_charOffset + data_5_3_charLength
            val data_5_5_charOffset = data_5_4_charOffset + data_5_4_charLength
            val data_5_6_charOffset = data_5_5_charOffset + data_5_5_charLength
            val data_5_1 = data_5.substring(0, data_5_2_charOffset)
            val data_5_2 = data_5.substring(data_5_2_charOffset, data_5_3_charOffset)
            val data_5_3 = data_5.substring(data_5_3_charOffset, data_5_4_charOffset)
            val data_5_4 = data_5.substring(data_5_4_charOffset, data_5_5_charOffset)
            val data_5_5 = data_5.substring(data_5_5_charOffset, data_5_6_charOffset)
            val data_5_6 = data_5.substring(data_5_6_charOffset)
            map_5 += hashMapOf(
                ResultType.Origin to """
                    $data_5_1
                    $data_5_2
                    $data_5_3
                    $data_5_4
                    $data_5_5
                    $data_5_6
                """.trimIndent(),
                ResultType.Analyzed to """
                    数据标识：$data_5_1
                    购电金额：$data_5_2
                    购电次数：$data_5_3
                    MAC 1：$data_5_4
                    客户编号：$data_5_5
                    MAC 2：$data_5_6
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_5[ResultType.Meaning]}
                    ${DATA_COUNT}26
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    数据标识（4B）
                    购电金额（4B）
                    购电次数（4B）
                    MAC 1（4B）
                    客户编号（6B）
                    MAC 2（4B）
                """.trimIndent()
            )

            map_6.parseDateHexData(
                data_6,
                data_6_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5,
                map_6
            )
        }

        private fun parse_0207_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "权限数据")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥密文")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")

            val data_1_byteLength = 8
            val data_2_byteLength = 4
            val data_3_byteLength = 48
            val data_4_byteLength = 32 * 20 + 16
            val data_5_byteLength = 7

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    身份认证产生的随机数
                """.trimIndent()
            }

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            val data_4_1 = data_4.substring(0, data_4.length - 32)
            val data_4_2 = data_4.substring(data_4.length - 32)
            val meterKeyCharLength = 64
            val data_4_1_origin = StringBuffer()
            val data_4_1_analyzed = StringBuffer()
            var key: String
            var keyNum = 1
            for (i in data_4_1.indices step meterKeyCharLength) {
                key = data_4_1.substring(i, i + meterKeyCharLength) + "\n|"
                data_4_1_origin.append(key)
                data_4_1_analyzed.append("密钥 ${keyNum}：$key")
                keyNum++
            }
            map_4 += hashMapOf(
                ResultType.Origin to """
                    |$data_4_1_origin
                    |$data_4_2
                """.trimMargin(),
                ResultType.Analyzed to """
                    |$data_4_1_analyzed
                    |$data_4_2
                """.trimMargin(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_4[ResultType.MeaningDetails]}
                    ${DATA_COUNT}32 * 20 + 16  (656)
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    密钥 1 ... 密钥 20
                    密文数据
                """.trimIndent()
            )

            map_5.parseDateHexData(
                data_5,
                data_5_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5
            )
        }

        private fun parse_0206_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "权限数据")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥密文")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")
            val map_6 = hashMapOf<ResultType, String>(ResultType.Meaning to "密钥状态")

            val data_1_byteLength = 8
            val data_2_byteLength = 4
            val data_3_byteLength = 48
            val data_4_byteLength = 32 * 6 + 16
            val data_5_byteLength = 7
            val data_6_byteLength = 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2
            val data_6_offset = data_5_offset + data_5_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, data_6_offset)
            val data_6 = frame.substring(data_6_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    身份认证产生的随机数
                """.trimIndent()
            }

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            val data_4_1 = data_4.substring(0, data_4.length - 32)
            val data_4_2 = data_4.substring(data_4.length - 32)
            val meterKeyCharLength = 64
            val data_4_1_origin = StringBuffer()
            val data_4_1_analyzed = StringBuffer()
            var key: String
            var keyNum = 1
            for (i in data_4_1.indices step meterKeyCharLength) {
                key = data_4_1.substring(i, i + meterKeyCharLength) + "\n|"
                data_4_1_origin.append(key)
                data_4_1_analyzed.append("密钥 ${keyNum}：$key")
                keyNum++
            }
            map_4 += hashMapOf(
                ResultType.Origin to """
                    |$data_4_1_origin
                    |$data_4_2
                """.trimMargin(),
                ResultType.Analyzed to """
                    |$data_4_1_analyzed
                    |$data_4_2
                """.trimMargin(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_4[ResultType.MeaningDetails]}
                    ${DATA_COUNT}32 * 6 + 16  (208)
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    密钥 1 ... 密钥 6
                    密文数据
                """.trimIndent()
            )

            map_5.parseDateHexData(
                data_5,
                data_5_byteLength
            )

            map_6.parseDecHexData(
                data_6,
                data_6_byteLength,
                meaning = "密钥状态：" + when (data_6.parseHexAsDecInt()) {
                    0x00 -> "密钥恢复"
                    0x01 -> "密钥下装"
                    else -> "未知状态"
                }
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    00：密钥恢复
                    01：密钥下装
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5,
                map_6
            )
        }

        private fun parse_0205_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "校时权限")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据标识")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "参数值")
            val map_6 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")
            val map_7 = hashMapOf<ResultType, String>(ResultType.Meaning to "星期")
            val map_8 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")

            val data_1_byteLength = 8
            val data_2_byteLength = 4
            val data_3_byteLength = 48
            val data_4_byteLength = 4
            val data_6_byteLength = 4
            val data_7_byteLength = 1
            val data_8_byteLength = 7
            val data_5_byteLength =
                dataDomainByteLength - (data_1_byteLength + data_2_byteLength +
                        data_3_byteLength + data_4_byteLength + data_6_byteLength +
                        data_7_byteLength + data_8_byteLength)

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2
            val data_6_offset = data_5_offset + data_5_byteLength * 2
            val data_7_offset = data_6_offset + data_6_byteLength * 2
            val data_8_offset = data_7_offset + data_7_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, data_6_offset)
            val data_6 = frame.substring(data_6_offset, data_7_offset)
            val data_7 = frame.substring(data_7_offset, data_8_offset)
            val data_8 = frame.substring(data_8_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    身份认证产生的随机数
                """.trimIndent()
            }

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parsePlainHexData(
                data_4,
                data_4_byteLength
            )

            map_5.parsePlainHexData(
                data_5,
                data_5_byteLength
            )

            map_6.parsePlainHexData(
                data_6,
                data_6_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    MAC值是数据标示及参数值的MAC
                """.trimIndent()
            }

            map_7.parseDecHexData(
                data_7,
                data_7_byteLength,
                meaning = "星期 " + when (data_7.parseHexAsDecInt()) {
                    1 -> "一"
                    2 -> "二"
                    3 -> "三"
                    4 -> "四"
                    5 -> "五"
                    6 -> "六"
                    7 -> "日"
                    else -> "?"
                }
            )

            map_8.parseDateHexData(
                data_8,
                data_8_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5,
                map_6,
                map_7,
                map_8
            )
        }

        private fun parse_0204_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "参数设置权限")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "参数类型")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据标识")
            val map_6 = hashMapOf<ResultType, String>(ResultType.Meaning to "参数值")
            val map_7 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")
            val map_8 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")

            val data_1_byteLength = 8
            val data_2_byteLength = 4
            val data_3_byteLength = 48
            val data_4_byteLength = 1
            val data_5_byteLength = 4
            val data_7_byteLength = 4
            val data_8_byteLength = 7
            val data_6_byteLength =
                dataDomainByteLength - (data_1_byteLength + data_2_byteLength +
                        data_3_byteLength + data_4_byteLength + data_5_byteLength +
                        data_7_byteLength + data_8_byteLength)

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2
            val data_6_offset = data_5_offset + data_5_byteLength * 2
            val data_7_offset = data_6_offset + data_6_byteLength * 2
            val data_8_offset = data_7_offset + data_7_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, data_6_offset)
            val data_6 = frame.substring(data_6_offset, data_7_offset)
            val data_7 = frame.substring(data_7_offset, data_8_offset)
            val data_8 = frame.substring(data_8_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    身份认证产生的随机数
                """.trimIndent()
            }

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parseDecHexData(
                data_4,
                data_4_byteLength,
                meaning = "参数类型：" + when (data_4.parseHexAsDecInt()) {
                    0x03 -> "二类参数"
                    0x05 -> "一类参数"
                    0x06 -> "一套费率"
                    0x07 -> "备用套费率"
                    else -> "未知参数类型"
                }
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    03：二类参数
                    05：一类参数
                    06：一套费率
                    07：备用套费率
                """.trimIndent()
            }

            map_5.parsePlainHexData(
                data_5,
                data_5_byteLength
            )

            map_6.parsePlainHexData(
                data_6,
                data_6_byteLength
            )

            map_7.parsePlainHexData(
                data_7,
                data_7_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    参数类型为 05、06、07时，MAC 值是参数值的 MAC
                    参数类型为 03 时，MAC 值是数据标示及参数值的 MAC
                """.trimIndent()
            }

            map_8.parseDateHexData(
                data_8,
                data_8_byteLength
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5,
                map_6,
                map_7,
                map_8
            )
        }

        private fun parse_0203_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "远程控制权限")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "控制数据")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")

            val data_1_byteLength = 8
            val data_2_byteLength = 4
            val data_3_byteLength = 48
            val data_4_byteLength = 12
            val data_5_byteLength = 7

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补0 x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    身份认证产生的随机数
                """.trimIndent()
            }

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            val ctlCode = data_4.substring(0, 4)
            val endTime = data_4.substring(4, 16)
            val mac = data_4.substring(16)
            map_4 += hashMapOf(
                ResultType.Origin to """
                    ${ctlCode.toZeroPrefixHexString(2)}
                    ${endTime.toZeroPrefixHexString(6)}
                    $mac
                """.trimIndent(),
                ResultType.Analyzed to """
                    命令码：${ctlCode.toZeroPrefixHexString(2)}
                    截止时间：${endTime.parseHexAsDateString()}
                    MAC：${mac.toZeroPrefixHexString(4)}
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_4[ResultType.Meaning]}
                    $DATA_COUNT$data_4_byteLength
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    命令码（2 字节）+ 截止时间（yyMMddHHmmss 6 字节）+ MAC（4 字节）
                """.trimIndent()
            )

            map_5.parseDateHexData(
                data_5,
                data_5_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    yyyyMMddHHmmss
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5
            )
        }

        private fun parse_0202_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "身份认证权限")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "公私钥标志")

            val data_1_byteLength = 8
            val data_2_byteLength = 48
            val data_3_byteLength = 7
            val data_4_byteLength = 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补0 x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parseDateHexData(
                data_3,
                data_3_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    yyyyMMddHHmmss
                """.trimIndent()
            }

            map_4.parseDecHexData(
                data_4,
                data_4_byteLength,
                meaning = "公私钥标志：" + when (data_4.parseHexAsDecInt()) {
                    0x00 -> "公钥"
                    else -> "私钥"
                }
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    00 为公钥，01 为私钥
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4
            )
        }

        private fun parse_0201_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "表号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 序列号")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数 1 密文")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "红外认证权限 1")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "红外认证权限 2")
            val map_6 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数 2")
            val map_7 = hashMapOf<ResultType, String>(ResultType.Meaning to "掌机当前时间")
            val map_8 = hashMapOf<ResultType, String>(ResultType.Meaning to "公私钥标志")

            val data_1_byteLength = 8
            val data_2_byteLength = 8
            val data_3_byteLength = 8
            val data_4_byteLength = 48
            val data_5_byteLength = 48
            val data_6_byteLength = 8
            val data_7_byteLength = 7
            val data_8_byteLength = 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2
            val data_6_offset = data_5_offset + data_5_byteLength * 2
            val data_7_offset = data_6_offset + data_6_byteLength * 2
            val data_8_offset = data_7_offset + data_7_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, data_6_offset)
            val data_6 = frame.substring(data_6_offset, data_7_offset)
            val data_7 = frame.substring(data_7_offset, data_8_offset)
            val data_8 = frame.substring(data_8_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    高位在前（非颠倒），高 2 字节补 0x00
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parsePlainHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parsePlainHexData(
                data_4,
                data_4_byteLength
            )

            map_5.parsePlainHexData(
                data_5,
                data_5_byteLength
            )

            map_6.parsePlainHexData(
                data_6,
                data_6_byteLength
            )

            map_7.parseDateHexData(
                data_7,
                data_7_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                 yyyyMMddHHmmss
             """.trimIndent()
            }

            map_8.parseDecHexData(
                data_8,
                data_8_byteLength,
                meaning = "公私钥标志：" + when (data_8.parseHexAsDecInt()) {
                    0x00 -> "公钥"
                    else -> "私钥"
                }
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    00 为公钥，01 为私钥
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5,
                map_6,
                map_7,
                map_8
            )
        }

        private fun parse_0189_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            // 0189 和 0187 的解析方式一样
            parse_0187_DataDomain(frame, resultList)
        }

        private fun parse_0187_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "MAC")

            val data_1_byteLength = 4

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            resultList.add(map_1)
        }

        private fun parse_0185_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据")

            val data_1_byteLength = 4

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            resultList.add(map_1)
        }

        private fun parse_0184_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "返回数据")

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            val (data_1_1, data_1_2) = data_1.parse_2_N_HexData()
            map_1 += hashMapOf(
                ResultType.Origin to """
                    $data_1_1
                    $data_1_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    返回数据长度：${data_1_1.parseHexAsDecInt()}
                    返回数据 ---- N 字节明文：
                    $data_1_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_1[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    返回数据长度（2 字节 LHLL）+ 具体数据（ N 字节明文）
                """.trimIndent()
            )

            resultList.add(map_1)
        }

        private fun parse_0183_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "返回数据")

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex - 8)

            val (data_1_1, data_1_2) = data_1.parse_2_N_HexData()
            val mac = data_1.substring(dataDomainCharEndIndex - 8, dataDomainCharEndIndex)

            map_1 += hashMapOf(
                ResultType.Origin to """
                    $data_1_1
                    $data_1_2
                    $mac
                """.trimIndent(),
                ResultType.Analyzed to """
                    返回数据长度：${data_1_1.parseHexAsDecInt()}
                    返回数据 ---- N 字节密文：
                    $data_1_2
                    返回数据 ---- MAC：
                    $mac
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_1[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    返回数据长度（2 字节 LHLL）+ 具体数据（ N 字节密文 + MAC）
                """.trimIndent()
            )

            resultList.add(map_1)
        }

        private fun parse_0182_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密文 M2")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "M2 签名")

            val data_1_byteLength = 48
            val data_2_byteLength = 64

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0181_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 类型")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数")

            val data_1_byteLength = 1
            //val data_2_byteLength= dataDomainByteLength-data_1_byteLength

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                "ESAM 类型：" + parseEsamType(data_1)
            ) { _, _, byteCountDes, dataFormatDes, meaningDetailsDes, _ ->
                """
                    |${DATA_NAME}ESAM 类型
                    |$byteCountDes
                    |$dataFormatDes
                    |$meaningDetailsDes
                    |   01：C-ESAM
                    |   02：Y-ESAM
                """.trimMargin()
            }

            // S 不为 0 则不解析随机数这一数据项
            if (S == 0x00) {
                val (data_2_1, data_2_2) = data_2.parse_2_N_HexData()
                map_2 += hashMapOf(
                    ResultType.Origin to """
                        $data_2_1
                        $data_2_2
                    """.trimIndent(),
                    ResultType.Analyzed to """
                        数据长度：${data_2_1.parseHexAsDecInt()}
                        数据内容：
                        $data_2_2
                    """.trimIndent(),
                    ResultType.MeaningDetails to """
                        $DATA_NAME${map_2[ResultType.Meaning]}
                        ${DATA_COUNT}2 + N
                        $DATA_FORMAT_HEX
                        $DATA_MEANING_DETAILS
                    """.trimIndent()
                )
            }

            resultList.add(map_1)
            if (S == 0x00) resultList.add(map_2)
        }

        private fun parse_010A_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据长度")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据")

            val data_1_byteLength = 2
            val data_2_byteLength = dataDomainByteLength - data_1_byteLength

            //val data_3_offset= dataDomainCharStartIndex+data_1_byteLength*2

            val (data_1, data_2) = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
                .parse_2_N_HexData()

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            val data_2_1 = data_2.substring(0, data_2_byteLength * 2 - 8)
            val mac = data_2.substring(data_2_byteLength * 2 - 8)
            map_2 += hashMapOf(
                ResultType.Origin to """
                    $data_2_1
                    $mac
                """.trimIndent(),
                ResultType.Analyzed to """
                    明文数据：$data_2_1
                    MAC：$mac
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    ${DATA_COUNT}N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    明文数据 + MAC
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0109_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据")

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            val (data_1_1, data_1_2) = data_1.parse_2_N_HexData()

            map_1 += hashMapOf(
                ResultType.Origin to """
                    $data_1_1
                    $data_1_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    数据长度：${data_1_1.parseHexAsDecInt()}
                    数据内容：
                    $data_1_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_1[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                """.trimIndent()
            )

            resultList.add(map_1)
        }

        private fun parse_0108_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数 M")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数长度")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据")

            val data_1_byteLengt = 16
            val data_2_byteLength = 2
            val data_3_byteLength = dataDomainByteLength - (data_1_byteLengt + data_2_byteLength)

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLengt * 2
            //val data_3_offset=data_2_offset+data_2_byteLength*2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val (data_2, data_3) = frame.substring(data_2_offset, dataDomainCharEndIndex)
                .parse_2_N_HexData()

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLengt
            )

            map_2.parseDecHexData(
                data_2,
                data_2_byteLength
            )

            val data_3_1 = data_3.substring(0, data_3_byteLength * 2 - 8)
            val mac = data_3.substring(data_3_byteLength * 2 - 8)
            map_3 += hashMapOf(
                ResultType.Origin to """
                    $data_3_1
                    $mac
                """.trimIndent(),
                ResultType.Analyzed to """
                    明文数据：$data_3_1
                    MAC：$mac
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_3[ResultType.Meaning]}
                    ${DATA_COUNT}N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    明文数据 + MAC
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3
            )
        }

        private fun parse_0107_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数 M")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据")

            val data_1_byteLength = 16
            //val data_2_byteLength= dataDomainByteLength-data_1_byteLength

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            val (data_2_1, data_2_2) = data_2.parse_2_N_HexData()
            map_2 += hashMapOf(
                ResultType.Origin to """
                    $data_2_1
                    $data_2_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    数据长度：${data_2_1.parseHexAsDecInt()}
                    数据内容:
                    $data_2_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    数据长度 + 数据内容
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0106_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据")

            val data_1_length = 16

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_length
            )

            resultList.add(map_1)
        }

        private fun parse_0105_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据")

            val data_1_byteLength = 32

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            resultList.add(map_1)
        }

        private fun parse_0104_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据")

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex - 8)

            val (data_1_1, data_1_2) = data_1.parse_2_N_HexData()
            val mac = data_1.substring(dataDomainCharEndIndex - 8, dataDomainCharEndIndex)

            map_1 += hashMapOf(
                ResultType.Origin to """
                    $data_1_1
                    $data_1_2
                    $mac
                """.trimIndent(),
                ResultType.Analyzed to """
                    输入数据长度：${data_1_1.parseHexAsDecInt()}
                    输入数据 ---- N 字节密文：
                    $data_1_2
                    输入数据 ---- MAC：
                    $mac
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_1[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    输入数据长度（2 字节 LHLL）+ 具体数据（ N 字节密文 + MAC）
                """.trimIndent()
            )

            resultList.add(map_1)
        }

        private fun parse_0103_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "输入数据")

            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            val (data_1_1, data_1_2) = data_1.parse_2_N_HexData()

            map_1 += hashMapOf(
                ResultType.Origin to """
                    $data_1_1
                    $data_1_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    输入数据长度：${data_1_1.parseHexAsDecInt()}
                    输入数据：
                    $data_1_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_1[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    输入数据长度（2 字节 LHLL）+ 具体数据（ N 字节 Data）
                """.trimIndent()
            )

            resultList.add(map_1)
        }

        private fun parse_0102_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "密文 M1")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "M1 签名")

            val data_1_byteLength = 32
            val data_2_byteLength = 64

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0101_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 类型")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "随机数长度")

            val data_1_byteLength = 1
            val data_2_byteLength = 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                "ESAM 类型：" + parseEsamType(data_1)
            ) { _, _, byteCountDes, dataFormatDes, meaningDetailsDes, _ ->
                """
                    |${DATA_NAME}ESAM 类型
                    |$byteCountDes
                    |$dataFormatDes
                    |$meaningDetailsDes
                    |   01：C-ESAM
                    |   02：Y-ESAM
                """.trimMargin()
            }

            map_2.parseDecHexData(
                data_2,
                data_2_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    长度取值：4，8，16
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_008A_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 类型")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "转发返回数据内容")

            val data_1_byteLength = 1
            //val data_2_byteLength = dataDomainByteLength - 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            val (data_2_1, data_2_2) = data_2.parse_2_N_HexData()

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                "ESAM 类型：" + parseEsamType(data_1)
            ) { _, _, byteCountDes, dataFormatDes, meaningDetailsDes, _ ->
                """
                    |${DATA_NAME}ESAM 类型
                    |$byteCountDes
                    |$dataFormatDes
                    |$meaningDetailsDes
                    |   01：C-ESAM
                    |   02：Y-ESAM
            """.trimMargin()
            }

            map_2 += hashMapOf(
                ResultType.Origin to """
                    $data_2_1
                    $data_2_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    转发数据内容长度：${data_2_1.parseHexAsDecInt()}
                    转发返回数据内容：
                    $data_2_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    ${map_2[ResultType.Meaning]}
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0089_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "文件编号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "操作模式")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "偏移地址")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据长度")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "读取数据")

            // 注：协议中 “文件编号” 的字节数为 1 ，这与 0009 的字节数冲突，这里采用 2 ，未经测试，可能会有问题
            val data_1_byteLength = 2
            val data_2_byteLength = 1
            val data_3_byteLength = 2
            val data_4_byteLength = 2
            val data_5_byteLength =
                dataDomainByteLength - (data_1_byteLength + data_2_byteLength + data_3_byteLength + data_4_byteLength)

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, dataDomainCharEndIndex)

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parseDecHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parseDecHexData(
                data_4,
                data_4_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    存储数据长度
                """.trimIndent()
            }

            map_5.parsePlainHexData(
                data_5,
                data_5_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    存储数据
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5
            )
        }

        private fun parse_0087_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            // 0087 和 0086 的解析方式一样
            parse_0086_DataDomain(frame, resultList)
        }

        private fun parse_0086_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 类型")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 返回数据内容")

            val data_1_byteLength = 1
            //val data_2_byteLength = dataDomainByteLength - 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            val (data_2_1, data_2_2) = data_2.parse_2_N_HexData()

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                "ESAM 类型：" + parseEsamType(data_1)
            ) { _, _, byteCountDes, dataFormatDes, meaningDetailsDes, _ ->
                """
                    |${DATA_NAME}ESAM 类型
                    |$byteCountDes
                    |$dataFormatDes
                    |$meaningDetailsDes
                    |   01：C-ESAM
                    |   02：Y-ESAM
                """.trimMargin()
            }

            map_2 += hashMapOf(
                ResultType.Origin to """
                    $data_2_1
                    $data_2_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    返回数据内容长度：${data_2_1.parseHexAsDecInt()}
                    返回数据内容：
                    $data_2_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    ${map_2[ResultType.Meaning]}
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        @ExperimentalUnsignedTypes
        private fun parse_0081_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "安全单元状态字")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "软件版本号")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "硬件版本号")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "C-ESAM 序列号")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "操作者代码")
            val map_6 = hashMapOf<ResultType, String>(ResultType.Meaning to "权限")
            val map_7 = hashMapOf<ResultType, String>(ResultType.Meaning to "权限掩码")
            val map_8 = hashMapOf<ResultType, String>(ResultType.Meaning to "操作者信息")
            val map_9 = hashMapOf<ResultType, String>(ResultType.Meaning to "Y-ESAM 序列号")
            val map_10 = hashMapOf<ResultType, String>(ResultType.Meaning to "Y-ESAM 对称密钥版本")
            val map_11 = hashMapOf<ResultType, String>(ResultType.Meaning to "主站证书版本号")
            val map_12 = hashMapOf<ResultType, String>(ResultType.Meaning to "终端证书版本号")
            val map_13 = hashMapOf<ResultType, String>(ResultType.Meaning to "主站证书序列号")
            val map_14 = hashMapOf<ResultType, String>(ResultType.Meaning to "终端证书序列号")
            val map_15 = hashMapOf<ResultType, String>(ResultType.Meaning to "当前计数器")
            val map_16 = hashMapOf<ResultType, String>(ResultType.Meaning to "转加密剩余次数")
            val map_17 = hashMapOf<ResultType, String>(ResultType.Meaning to "标签密钥版本")
            val map_18 = hashMapOf<ResultType, String>(ResultType.Meaning to "主站证书")
            val map_19 = hashMapOf<ResultType, String>(ResultType.Meaning to "终端证书")

            val data_1_byteLength = 1
            val data_2_byteLength = 3
            val data_3_byteLength = 3
            val data_4_byteLength = 8
            val data_5_byteLength = 4
            val data_6_byteLength = 1
            val data_7_byteLength = 8
            val data_8_byteLength = 30
            val data_9_byteLength = 8
            val data_10_byteLength = 16
            val data_11_byteLength = 1
            val data_12_byteLength = 1
            val data_13_byteLength = 16
            val data_14_byteLength = 16
            val data_15_byteLength = 4
            val data_16_byteLength = 4
            val data_17_byteLength = 8
            var data_18_byteLength by Delegates.notNull<Int>()
            val data_19_byteLength by Delegates.notNull<Int>()

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2
            val data_6_offset = data_5_offset + data_5_byteLength * 2
            val data_7_offset = data_6_offset + data_6_byteLength * 2
            val data_8_offset = data_7_offset + data_7_byteLength * 2
            val data_9_offset = data_8_offset + data_8_byteLength * 2
            val data_10_offset = data_9_offset + data_9_byteLength * 2
            val data_11_offset = data_10_offset + data_10_byteLength * 2
            val data_12_offset = data_11_offset + data_11_byteLength * 2
            val data_13_offset = data_12_offset + data_12_byteLength * 2
            val data_14_offset = data_13_offset + data_13_byteLength * 2
            val data_15_offset = data_14_offset + data_14_byteLength * 2
            val data_16_offset = data_15_offset + data_15_byteLength * 2
            val data_17_offset = data_16_offset + data_16_byteLength * 2
            val data_18_offset = data_17_offset + data_17_byteLength * 2
            var data_19_offset by Delegates.notNull<Int>()

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, data_6_offset)
            val data_6 = frame.substring(data_6_offset, data_7_offset)
            val data_7 = frame.substring(data_7_offset, data_8_offset)
            val data_8 = frame.substring(data_8_offset, data_9_offset)
            val data_9 = frame.substring(data_9_offset, data_10_offset)
            val data_10 = frame.substring(data_10_offset, data_11_offset)
            val data_11 = frame.substring(data_11_offset, data_12_offset)
            val data_12 = frame.substring(data_12_offset, data_13_offset)
            val data_13 = frame.substring(data_13_offset, data_14_offset)
            val data_14 = frame.substring(data_14_offset, data_15_offset)
            val data_15 = frame.substring(data_15_offset, data_16_offset)
            val data_16 = frame.substring(data_16_offset, data_17_offset)
            val data_17 = frame.substring(data_17_offset, data_18_offset)
            val data_18 = frame.substring(data_18_offset)

            val esamStatus = data_1.parseHexAsDecInt()
            val esamWorkStatus = when ((esamStatus and 0xF0) ushr 4) {
                0x0000 -> "模块正常，可以接收指令"
                0x0001 -> "存贮器错误"
                else -> "未知工作状态"
            }
            val c_esamStatus = when ((esamStatus and 0x0C) ushr 2) {
                0x00 -> "C-ESAM 正常"
                0x01 -> "C-ESAM 故障"
                else -> "保留，状态未定义"
            }
            val y_esamStatus = when (esamStatus and 0x03) {
                0x00 -> "Y-ESAM 正常"
                0x01 -> "Y-ESAM 故障"
                else -> "保留，状态未定义"
            }
            map_1 += hashMapOf(
                ResultType.Origin to data_1.toZeroPrefixHexString(data_1_byteLength),
                ResultType.Analyzed to """
                    工作状态：$esamWorkStatus
                    操作员 ESAM 状态：$c_esamStatus
                    业务 ESAM 状态：$y_esamStatus
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    :$DATA_NAME${map_1[ResultType.Meaning]}
                    :$DATA_COUNT$data_1_byteLength
                    :$DATA_FORMAT_HEX
                    :$DATA_MEANING_DETAILS
                    :
                    :|--------------------------------------------------------
                    :|  D7  |  D6  |  D5  |  D4  |  D3  |  D2  |  D1  |  D0  |
                    :|---------------------------|-------------|-------------|
                    :| 工作状态                   | C-ESAM 状态  | Y-ESAM 状态 |
                    :|---------------------------|---------------------------|
                    :| 0000：模块正常，可接收指令   | 00 ESAM 正常 | 00 ESAM 正常|
                    :| 0001：存贮器错误            | 01 ESAM 故障 | 01 ESAM 故障|
                    :| 0002：保留                 | 1X 保留      | 1X 保留     |
                    :|--------------------------------------------------------
                    :
                """.trimMargin(":")
            )

            val bootVersion = data_2.substring(0, 2)
            val appVersion = data_2.substring(2)
            map_2 += hashMapOf(
                ResultType.Origin to data_2.toZeroPrefixHexString(data_2_byteLength),
                ResultType.Analyzed to """
                    boot 版本：$bootVersion （${bootVersion.parseHexAsDecInt()}）
                    APP 版本：$appVersion （${appVersion.parseHexAsDecInt()}）
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    $DATA_COUNT$data_2_byteLength
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    第一个字节是 boot 程序版本号
                    后两个字节是 APP 程序版本号
                """.trimIndent()
            )

            val v1 = data_3.substring(0, 2)
            val v2 = data_3.substring(2)
            map_3 += hashMapOf(
                ResultType.Origin to data_3.toZeroPrefixHexString(data_3_byteLength),
                ResultType.Analyzed to """
                    安全单元改版编号：$v1 （${v1.parseHexAsDecInt()}）
                    安全单元本版编号：$v2 （${v2.parseHexAsDecInt()}）
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_3[ResultType.Meaning]}
                    $DATA_COUNT$data_3_byteLength
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    第一个字节是安全单元改版编号
                    后二个字节是安全单元本版编号
                """.trimIndent()
            )

            map_4.parsePlainHexData(
                data_4,
                data_4_byteLength
            )

            map_5.parsePlainHexData(
                data_5,
                data_5_byteLength
            ) { meaning, _, _, _, _, preDes ->
                preDes + """
                    $meaning
                """.trimIndent()
            }

            map_6.parseDecHexData(
                data_6,
                data_6_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    有效范围：1-15
                """.trimIndent()
            }

            map_7.parsePlainHexData(
                data_7,
                data_7_byteLength
            )

            val name = data_8.substring(0, 10).parseHexAsUTF8String()
            val unit = data_8.substring(10).parseHexAsUTF8String()
            map_8 += hashMapOf(
                ResultType.Origin to data_8.toZeroPrefixHexString(data_8_byteLength),
                ResultType.Analyzed to """
                    姓名：$name
                    单位：$unit
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_8[ResultType.Meaning]}
                    $DATA_COUNT$data_8_byteLength
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    姓名和单位信息（姓名 5 个汉字；单位信息 10 个汉字）
                """.trimIndent()
            )

            map_9.parsePlainHexData(
                data_9,
                data_9_byteLength
            )

            map_10.parsePlainHexData(
                data_10,
                data_19_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    最新更新的对称密钥密钥版本，初始值为全00
                """.trimIndent()
            }

            map_11.parseDecHexData(
                data_11,
                data_11_byteLength
            )

            map_12.parseDecHexData(
                data_12,
                data_12_byteLength
            )

            map_13.parsePlainHexData(
                data_13,
                data_13_byteLength
            )

            map_14.parsePlainHexData(
                data_14,
                data_14_byteLength
            )

            map_15.parseDecHexData(
                data_15,
                data_15_byteLength
            )

            map_16.parseDecHexData(
                data_16,
                data_16_byteLength
            )

            map_17.parsePlainHexData(
                data_17,
                data_17_byteLength
            )

            val (data_18_1, data_18_2) = data_18.parse_2_N_HexData()
            data_18_byteLength = 2 + data_18_1.parseHexAsDecInt()
            map_18 += hashMapOf(
                ResultType.Origin to """
                    $data_18_1
                    $data_18_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    证书长度：${data_18_1.parseHexAsDecInt()}
                    证书数据：
                    $data_18_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_18[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    证书长度 + 证书数据
                """.trimIndent()
            )

            data_19_offset = data_18_offset + data_18_byteLength * 2
            val data_19: String = frame.substring(data_19_offset, dataDomainCharEndIndex)
            val (data_19_1, data_19_2) = data_19.parse_2_N_HexData()
            //data_19_byteLength = 2 + data_19_1.parseHexAsDecInt()
            map_19 += hashMapOf(
                ResultType.Origin to """
                    $data_19_1
                    $data_19_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    证书长度：${data_19_1.parseHexAsDecInt()}
                    证书数据：
                    $data_19_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_19[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    证书长度 + 证书数据
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5,
                map_6,
                map_7,
                map_8,
                map_9,
                map_10,
                map_11,
                map_12,
                map_13,
                map_14,
                map_15,
                map_16,
                map_17,
                map_18,
                map_19
            )

        }

        private fun parse_000A_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 类型")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "转发数据内容")

            val data_1_byteLength = 1
            //val data_2_byteLength = dataDomainByteLength - 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            val (data_2_1, data_2_2) = data_2.parse_2_N_HexData()

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                "ESAM 类型：" + parseEsamType(data_1)
            ) { _, _, byteCountDes, dataFormatDes, meaningDetailsDes, _ ->
                """
                    |${DATA_NAME}ESAM 类型
                    |$byteCountDes
                    |$dataFormatDes
                    |$meaningDetailsDes
                    |   01：C-ESAM
                    |   02：Y-ESAM
            """.trimMargin()
            }

            map_2 += hashMapOf(
                ResultType.Origin to """
                    $data_2_1
                    $data_2_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    转发数据内容长度：${data_2_1.parseHexAsDecInt()}
                    转发数据内容：
                    $data_2_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    ${map_2[ResultType.Meaning]}
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0009_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "文件编号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "操作模式")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "偏移地址")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据长度")

            val data_1_byteLength = 2
            val data_2_byteLength = 1
            val data_3_byteLength = 2
            val data_4_byteLength = 2

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, dataDomainCharEndIndex)

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parseDecHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parseDecHexData(
                data_4,
                data_4_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    存储数据长度
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4
            )
        }

        private fun parse_0008_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "文件编号")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "操作模式")
            val map_3 = hashMapOf<ResultType, String>(ResultType.Meaning to "偏移地址")
            val map_4 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据长度")
            val map_5 = hashMapOf<ResultType, String>(ResultType.Meaning to "数据内容")

            val data_1_byteLength = 2
            val data_2_byteLength = 1
            val data_3_byteLength = 2
            val data_4_byteLength = 2
            val data_5_byteLength =
                dataDomainByteLength - (data_1_byteLength + data_2_byteLength + data_3_byteLength + data_4_byteLength)

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, dataDomainCharEndIndex)

            map_1.parseDecHexData(
                data_1,
                data_1_byteLength
            )

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength
            )

            map_3.parseDecHexData(
                data_3,
                data_3_byteLength
            )

            map_4.parseDecHexData(
                data_4,
                data_4_byteLength
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    存储数据长度
                """.trimIndent()
            }

            map_5.parsePlainHexData(
                data_5,
                data_5_byteLength
            ) { meaning, _, _, _, _, preDes ->
                preDes + """
                    $meaning
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2,
                map_3,
                map_4,
                map_5
            )
        }

        private fun parse_0007_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            // 0007 和 0006 的解析方式一样
            parse_0006_DataDomain(frame, resultList)
        }

        private fun parse_0006_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "ESAM 类型")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "发行数据内容")

            val data_1_byteLength = 1
            //val data_2_byteLength = dataDomainByteLength - 1

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            val (data_2_1, data_2_2) = data_2.parse_2_N_HexData()

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                "ESAM 类型：" + parseEsamType(data_1)
            ) { _, _, byteCountDes, dataFormatDes, meaningDetailsDes, _ ->
                """
                    |${DATA_NAME}ESAM 类型
                    |$byteCountDes
                    |$dataFormatDes
                    |$meaningDetailsDes
                    |   01：C-ESAM
                    |   02：Y-ESAM
                """.trimMargin()
            }

            map_2 += hashMapOf(
                ResultType.Origin to """
                    $data_2_1
                    $data_2_2
                """.trimIndent(),
                ResultType.Analyzed to """
                    发行数据内容长度：${data_2_1.parseHexAsDecInt()}
                    发行数据内容：
                    $data_2_2
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    $DATA_NAME${map_2[ResultType.Meaning]}
                    ${DATA_COUNT}2 + N
                    $DATA_FORMAT_HEX
                    $DATA_MEANING_DETAILS
                    ${map_2[ResultType.Meaning]}
                """.trimIndent()
            )

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0005_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "解锁数据")
            val data_1_byteLength = 28
            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)

            val data_1_1_byteLength = 8
            val data_1_2_byteLength = 16
            val data_1_3_byteLength = 2
            val data_1_4_byteLength = 2

            val data_1_2_offset = 0 + data_1_1_byteLength * 2
            val data_1_3_offset = data_1_2_offset + data_1_2_byteLength * 2
            val data_1_4_offset = data_1_3_offset + data_1_3_byteLength * 2

            val data_1_1 = data_1.substring(0, data_1_2_offset)    // 认证数据
            val data_1_2 = data_1.substring(data_1_2_offset, data_1_3_offset)  // 密码密文
            val data_1_3 = data_1.substring(data_1_3_offset, data_1_4_offset)  // 最大密码尝试次数
            val data_1_4 = data_1.substring(data_1_4_offset)  // 剩余密码尝试次数

            map_1 += hashMapOf(
                ResultType.Origin to """
                    ${data_1_1.toZeroPrefixHexString(data_1_1_byteLength)}
                    ${data_1_2.toZeroPrefixHexString(data_1_2_byteLength)}
                    ${data_1_3.toZeroPrefixHexString(data_1_3_byteLength)}
                    ${data_1_4.toZeroPrefixHexString(data_1_4_byteLength)}
                """.trimIndent(),
                ResultType.Analyzed to """
                    认证数据：${data_1_1.toZeroPrefixHexString(data_1_1_byteLength)}
                    密码密文：${data_1_2.toZeroPrefixHexString(data_1_2_byteLength)}
                    最大密码尝试次数：${data_1_3.toZeroPrefixHexString(data_1_3_byteLength)}
                    剩余密码尝试次数：${data_1_4.toZeroPrefixHexString(data_1_4_byteLength)}
                """.trimIndent(),
                ResultType.MeaningDetails to """
                    |$DATA_NAME${map_1[ResultType.Meaning]}
                    |$DATA_COUNT$data_1_byteLength
                    |$DATA_FORMAT_HEX
                    |$DATA_MEANING_DETAILS
                    |   认证数据（8B）
                    |   密码密文（16B）
                    |   最大密码尝试次数（2B）
                    |   剩余密码尝试次数（2B）
                """.trimMargin()
            )

            resultList.add(map_1)
        }

        private fun parse_0004_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "认证数据")
            val data_1_byteLength = 8
            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength
            ) { _, _, _, _, _, preDes -> preDes }
            resultList.add(map_1)
        }

        private fun parse_0003_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            /*
            关于操作员密码的编码处理方式请看 parse_0002_DataDomain 方法
             */
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "旧操作员密码")
            val map_2 = hashMapOf<ResultType, String>(ResultType.Meaning to "新操作员密码")

            val data_1_byteLength = 3
            val data_2_byteLength = 3

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                dataFormat = "BCD （8421）"
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    包含 0-9 数字
                """.trimIndent()
            }

            map_2.parsePlainHexData(
                data_2,
                data_2_byteLength,
                dataFormat = "BCD （8421）"
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    包含 0-9 数字
                """.trimIndent()
            }

            resultList.addResults(
                map_1,
                map_2
            )
        }

        private fun parse_0002_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            /*
            --------------------------------
            |       8421 BCD 编码方式       |
            --------------------------------
            |   十进制数    |   8421 码     |
            --------------------------------
            |       0      |    0000       |
            |       1      |    0001       |
            |       2      |    0010       |
            |       3      |    0011       |
            |       4      |    0100       |
            |       5      |    0101       |
            |       6      |    0110       |
            |       7      |    0111       |
            |       8      |    1000       |
            |       9      |    1001       |
            --------------------------------

            --------------------------------
            |             ASCII            |
            --------------------------------
            |   A - Z    |    0x41 - 0x5A  |
            |   a - z    |    0x61 - 0x7A  |
            --------------------------------

            注：
            1、因 2.0 安全单元通信协议中未对 BCD 的具体编码方式作说明，这里默认使用 8421 编码方式
            2、协议中写了操作员密码可以包含 A-Z、a-z 以及空格字符，但是实际这些字符的 ASCII 编码方式
                与 BCD 的编码方式有冲突（不止与 8421 的 BCD 编码方式冲突），至使无法区分出密码字节中
                哪些字节是 ASCII 编码，哪些字节是 BCD 编码，所以目前默认密码字节全是 BCD 编码，不支持
                解析 ASCII 编码的字符。
             */
            val map_1 = hashMapOf<ResultType, String>(ResultType.Meaning to "操作员密码")
            val data_1_byteLength = 3
            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
            map_1.parsePlainHexData(
                data_1,
                data_1_byteLength,
                dataFormat = "BCD （8421）"
            ) { _, _, _, _, _, preDes ->
                preDes + """
                    包含 0-9 数字
                """.trimIndent()
            }
            resultList.add(map_1)
        }

        private fun parseEsamType(esamType: String) = when (esamType) {
            "01" -> "C-ESAM"
            "02" -> "Y-ESAM"
            else -> "未知类型"
        }


        private fun origin(
            isTrimIndent: Boolean = true,
            block: () -> String
        ): Pair<ResultType, String> = ResultType.Origin to when (isTrimIndent) {
            true -> block().trimIndent()
            false -> block().trimMargin()
        }

        private fun analyzed(
            isTrimIndent: Boolean = true,
            block: () -> String
        ): Pair<ResultType, String> = ResultType.Origin to when (isTrimIndent) {
            true -> block().trimIndent()
            false -> block().trimMargin()
        }

        private fun meaningDetails(
            isTrimIndent: Boolean = true,
            block: () -> String
        ): Pair<ResultType, String> = ResultType.Origin to when (isTrimIndent) {
            true -> block().trimIndent()
            false -> block().trimMargin()
        }

        /** N 字节不确定长度 */
        private const val UNCERTAIN_LENGTH = -1

        /** 2 + N 字节不确定长度 */
        private const val TWO_N = -2

        /**
         * 将数据项的原始的、分析后的以及详细信息添加到当前 HashMap 中
         *
         * @param byteCount 数据项字节长度
         * @param pairs 数据项字段
         * @param meaning 数据项名称或简要意义
         * @param dataFormat 数据项数据格式，默认为 "HEX"
         * @param descriptionBlock 填充意义详细描述，接收 dataMeaningDes（数据项描述）、byteCountDes（字节数量描述）、
         *      dataFormatDes（数据格式描述）、meaningDetailsDes（数据项详细描述）、descriptionBlock（预处理描述模板）五个参数
         *
         */
        private fun HashMap<ResultType, String>.append(
            byteCount: Int = UNCERTAIN_LENGTH,
            vararg pairs: Pair<ResultType, String>,
            meaning: String = this[ResultType.Meaning]!!,
            dataFormat: String = "HEX",
            descriptionBlock: (
                meaning: String,
                dataMeaningDes: String,
                byteCountDes: String,
                dataFormatDes: String,
                meaningDetailsDes: String,
                preDes: String
            ) -> String = { _, _, _, _, _, preDes -> preDes }
        ) {
            this.putAll(pairs)
            this[ResultType.Meaning] = meaning
            val dataMeaningDes = "$DATA_NAME$${this[ResultType.Meaning]}"
            val byteCountDes = "$DATA_COUNT${
                when (byteCount) {
                    UNCERTAIN_LENGTH -> "N"
                    TWO_N -> "2 + N"
                    else -> byteCount
                }
            }"
            val dataFormatDes = "$DATA_FORMAT$dataFormat"
            val meaningDetailsDes = DATA_MEANING_DETAILS
            val preDes = """
                $dataMeaningDes
                $byteCountDes
                $dataFormatDes
                $meaningDetailsDes
                
            """.trimIndent()
            this[ResultType.MeaningDetails] = descriptionBlock(
                meaning,
                dataMeaningDes,
                byteCountDes,
                dataFormatDes,
                meaningDetailsDes,
                preDes
            )
        }

        /**
         * 将数据项当作日期数据解析到当前 HashMap 中，日期格式为 yyyyMMddHHmmss
         *
         * @param data 原始数据
         * @param meaning 数据项名称或简要意义
         * @param byteCount 数据项字节长度
         * @param dataFormat 数据项数据格式，默认为 "HEX"
         * @param descriptionBlock 填充意义详细描述，接收 dataMeaningDes（数据项描述）、byteCountDes（字节数量描述）、
         *      dataFormatDes（数据格式描述）、meaningDetailsDes（数据项详细描述）、descriptionBlock（预处理描述模板）五个参数
         *
         */
        private fun HashMap<ResultType, String>.parseDateHexData(
            data: String,
            byteCount: Int,
            meaning: String = this[ResultType.Meaning]!!,
            dataFormat: String = "HEX",
            descriptionBlock: (
                meaning: String,
                dataMeaningDes: String,
                byteCountDes: String,
                dataFormatDes: String,
                meaningDetailsDes: String,
                preDes: String
            ) -> String = { _, _, _, _, _, preDes -> preDes }
        ) {
            this.parseData(
                data,
                byteCount,
                meaning,
                dataFormat,
                ParseType.DateType,
                descriptionBlock
            )
        }

        /**
         * 将数据项当作十进制数据解析到当前 HashMap 中
         *
         * @param data 原始数据
         * @param meaning 数据项名称或简要意义
         * @param byteCount 数据项字节长度
         * @param dataFormat 数据项数据格式，默认为 "HEX"
         * @param descriptionBlock 填充意义详细描述，接收 dataMeaningDes（数据项描述）、byteCountDes（字节数量描述）、
         *      dataFormatDes（数据格式描述）、meaningDetailsDes（数据项详细描述）、descriptionBlock（预处理描述模板）五个参数
         *
         */
        private fun HashMap<ResultType, String>.parseDecHexData(
            data: String,
            byteCount: Int,
            meaning: String = this[ResultType.Meaning]!!,
            dataFormat: String = "HEX",
            descriptionBlock: (
                meaning: String,
                dataMeaningDes: String,
                byteCountDes: String,
                dataFormatDes: String,
                meaningDetailsDes: String,
                preDes: String
            ) -> String = { _, _, _, _, _, preDes -> preDes }
        ) {
            this.parseData(
                data,
                byteCount,
                meaning,
                dataFormat,
                ParseType.DecType,
                descriptionBlock
            )
        }

        /**
         * 将无需特殊解析的通用数据项解析到当前 HashMap 中
         *
         * @param data 原始数据
         * @param meaning 数据项名称或简要意义
         * @param byteCount 数据项字节长度
         * @param dataFormat 数据项数据格式，默认为 "HEX"
         * @param descriptionBlock 填充意义详细描述，接收 dataMeaningDes（数据项描述）、byteCountDes（字节数量描述）、
         *      dataFormatDes（数据格式描述）、meaningDetailsDes（数据项详细描述）、descriptionBlock（预处理描述模板）五个参数
         *
         */
        private fun HashMap<ResultType, String>.parsePlainHexData(
            data: String,
            byteCount: Int,
            meaning: String = this[ResultType.Meaning]!!,
            dataFormat: String = "HEX",
            descriptionBlock: (
                meaning: String,
                dataMeaningDes: String,
                byteCountDes: String,
                dataFormatDes: String,
                meaningDetailsDes: String,
                preDes: String
            ) -> String = { _, _, _, _, _, preDes -> preDes }
        ) {
            this.parseData(
                data,
                byteCount,
                meaning,
                dataFormat,
                ParseType.HexType,
                descriptionBlock
            )
        }

        private sealed class ParseType {
            /**
             * 十六进制解析类型
             */
            object HexType : ParseType()

            /**
             * 十进制解析类型
             */
            object DecType : ParseType()

            /**
             *  日期解析类型
             */
            object DateType : ParseType()
        }

        private const val DATA_NAME = "数据名称："
        private const val DATA_COUNT = "字节数："
        private const val DATA_FORMAT = "数据格式："
        private const val DATA_FORMAT_HEX = "数据格式：HEX"
        private const val DATA_MEANING_DETAILS = "意义："

        private fun HashMap<ResultType, String>.parseData(
            data: String,
            byteCount: Int,
            meaning: String = this[ResultType.Meaning]!!,
            dataFormat: String = "HEX",
            parseType: ParseType,
            descriptionBlock: (
                meaning: String,
                dataMeaningDes: String,
                byteCountDes: String,
                dataFormatDes: String,
                meaningDetailsDes: String,
                preDes: String
            ) -> String = { _, _, _, _, _, preDes -> preDes }
        ) {
            val hexData = data.toZeroPrefixHexString(byteCount)
            this[ResultType.Origin] = hexData
            this[ResultType.Analyzed] = when (parseType) {
                ParseType.HexType -> hexData
                ParseType.DecType -> data.parseHexAsDecString()
                ParseType.DateType -> data.parseHexAsDateString()
            }
            this[ResultType.Meaning] = meaning
            val dataMeaningDes = "$DATA_NAME${this[ResultType.Meaning]}"
            val byteCountDes = "$DATA_COUNT$byteCount"
            val dataFormatDes = "$DATA_FORMAT$dataFormat"
            val meaningDetailsDes = DATA_MEANING_DETAILS
            val preDes = """
                $dataMeaningDes
                $byteCountDes
                $dataFormatDes
                $meaningDetailsDes
                
            """.trimIndent()
            this[ResultType.MeaningDetails] = descriptionBlock(
                meaning,
                dataMeaningDes,
                byteCountDes,
                dataFormatDes,
                meaningDetailsDes,
                preDes
            )
        }

        private class DataOf2N(
            val byteLength: String,
            val dataContent: String
        ) {
            operator fun component1(): String = byteLength
            operator fun component2(): String = dataContent
        }

        /**
         * 拆分 2 + N 结构的字节字符串数据，前两个字节是大字节序的长度信息，余下的是数据内容。
         * 拆分的字节已经过添加 0 前缀处理。如果从帧里解析出的数据长度与实际数据长度不符，则取
         * 短的那个数据长度进行帧解析
         */
        private fun String.parse_2_N_HexData(): DataOf2N {
            val data_1_byteLength = 2
            var data_2_byteLength by Delegates.notNull<Int>()

            val data_2_offset = data_1_byteLength * 2
            val data_1 = this.substring(0, data_2_offset)
            val byteLengthFromFrame = data_1.parseHexAsDecInt()
            val realByteLength = this.length / 2 - data_1_byteLength
            data_2_byteLength = if (byteLengthFromFrame <= realByteLength)
                byteLengthFromFrame
            else
                realByteLength
            val data_2 = this.substring(data_2_offset, data_2_offset + data_2_byteLength * 2)

            return DataOf2N(
                byteLength = data_1.toZeroPrefixHexString(data_1_byteLength),
                dataContent = data_2.toZeroPrefixHexString(data_2_byteLength)
            )
        }

        /**
         * 按顺序将结果添加到结果列表中
         */
        private fun MutableList<HashMap<ResultType, String>>.addResults(vararg results: HashMap<ResultType, String>) =
            this.addAll(results)

        /**
         * 获取状态码含义
         *
         * @param F 主功能标识符
         * @param A 响应码
         */
        private fun Int.get_S_Meaning(F: Int, A: Int): String {
            when (this) {
                // 正常响应码
                0x00 -> "状态码：安全单元正常响应"
                // 通用错误码
                0xF1 -> "通用错误码：帧效验错"
                0xF2 -> "通用错误码：帧长度不符"
                0xF3 -> "通用错误码：操作员权限不够"
                0xF4 -> {
                    // 有特殊情况占用了 F4 错误码
                    when {
                        F == 0x01 && (A and 0x7F) == 0x09 ||
                                F == 0x03 && (A and 0x7F) == 0x04 ||
                                F == 0x05 && (A and 0x7F) == 0x03 -> ""
                        else -> "通用错误码：安全模块错误- 操作员卡操作失败"
                    }
                }
                0xF5 -> "通用错误码：安全模块错误-业务卡操作错误"
                0xF6 -> "通用错误码：安全单元与业务卡不同步"
                0xF7 -> "通用错误码：当前仅响应升级命令，只用于红外认证命令"
                else -> ""
            }.also {
                if (it.isNotEmpty()) return@get_S_Meaning it
            }
            // 非通用错误码
            val meaning = when (F) {
                0x00 -> when (A and 0x7F) {
                    0x01 -> when (this) {
                        0x01 -> "安全单元有问题"
                        0x02 -> "获取 C-ESAM 序列号失败"
                        0x03 -> "获取操作者代码失败"
                        0x04 -> "获取权限和权限掩码失败"
                        0x05 -> "获取操作者信息失败"
                        0x06 -> "获取 Y-ESAM 信息失败"
                        0x07 -> "获取转加密剩余次数失败"
                        0x08 -> "获取密钥版本失败"
                        0x09 -> "获取主站证书失败"
                        0x0A -> "获取终端证书失败"
                        else -> "未知状态码"
                    }
                    0x02 -> when (this) {
                        0x01 -> "获取密码密文、最大密码尝试次数、剩余密码尝试次数失败"
                        0x02 -> "最大密码尝试次数前后不相等"
                        0x03 -> "剩余密码尝试次数前后不相等"
                        0x04 -> "剩余密码次数为0"
                        0x05 -> "解密密码密文失败，安全单元锁定"
                        0x06 -> "密码尝试次数减1失败"
                        0x07 -> "密码不一致"
                        0x08 -> "恢复最大密码尝试次数失败"
                        0x09 -> "获取 Y-ESAM 序列号失败"
                        0x0A -> "获取 Y-ESAM 序列号随机数失败"
                        0x0B -> "加密随机数失败"
                        0x0C -> "外部认证失败"
                        else -> "未知状态码"
                    }
                    0x03 -> when (this) {
                        0x01 -> "获取密码密文、最大密码尝试次数、剩余密码尝试次数失败"
                        0x02 -> "最大密码尝试次数前后不相等"
                        0x03 -> "剩余密码尝试次数前后不相等"
                        0x04 -> "剩余密码次数为0"
                        0x05 -> "解密密码密文失败"
                        0x06 -> "密码不一致返回剩余密码尝试次数"
                        0x07 -> "恢复最大密码尝试次数失败"
                        0x08 -> "加密明文密码失败"
                        0x09 -> "修改密码失败"
                        0x0A -> "获取 Y-ESAM 序列号失败"
                        0x0B -> "获取 Y-ESAM 随机数失败"
                        0x0C -> "加密随机数失败"
                        0x0D -> "外部认证失败"
                        0x0E -> "解密修改后密码密文失败"
                        0x0F -> "新修改密码和输入密码不一致"
                        else -> "未知状态码"
                    }
                    0x04 -> when (this) {
                        0x01 -> "外部认证失败"
                        0x02 -> "清零失败"
                        else -> "未知状态码"
                    }
                    0x05 -> when (this) {
                        0x01 -> "外部认证失败"
                        0x02 -> "获取密码尝试次数失败"
                        0x03 -> "修改最大密码尝试次数失败"
                        0x04 -> "加密明文密码失败"
                        0x05 -> "修改操作员密码失败"
                        else -> "未知状态码"
                    }
                    0x06 -> when (this) {
                        0x01 -> "一般错误"
                        0x02 -> "ESAM 没有返回 0x55"
                        0x03 -> "ESAM 返回错误码"
                        else -> "未知状态码"
                    }
                    0x07 -> when (this) {
                        0x01 -> "一般错误"
                        0x02 -> "ESAM 没有返回 0x55"
                        0x03 -> "ESAM 返回错误码"
                        else -> "未知状态码"
                    }
                    0x08 -> when (this) {
                        0x01 -> "存储失败"
                        else -> "未知状态码"
                    }
                    0x09 -> when (this) {
                        0x01 -> "读取失败"
                        else -> "未知状态码"
                    }
                    0x0A -> when (this) {
                        0x01 -> "一般错误"
                        0x02 -> "ESAM 没有返回 0x55"
                        0x03 -> "ESAM 返回错误码"
                        else -> "未知状态码"
                    }
                    else -> "未知命令码"
                }
                0x01 -> when (A and 0xF7) {
                    0x01 -> when (this) {
                        0x01 -> "获取随机数失败"
                        else -> "未知状态码"
                    }
                    0x02 -> when (this) {
                        0x01 -> "身份认证失败"
                        else -> "未知状态码"
                    }
                    0x03 -> when (this) {
                        0x01 -> "计算失败"
                        else -> "未知状态码"
                    }
                    0x04 -> when (this) {
                        0x01 -> "计算失败"
                        else -> "未知状态码"
                    }
                    0x05 -> when (this) {
                        0x01 -> "转加密初始化失败"
                        else -> "未知状态码"
                    }
                    0x06 -> when (this) {
                        0x01 -> "设置离线计数失败"
                        else -> "未知状态码"
                    }
                    0x07 -> when (this) {
                        0x01 -> "Y-ESAM 计算失败"
                        else -> "未知状态码"
                    }
                    0x08 -> when (this) {
                        0x01 -> "验证失败"
                        else -> "未知状态码"
                    }
                    0x09 -> when (this) {
                        0x05 -> "打开文件目录失败"
                        0xF4 -> "计算 MAC 错误"
                        else -> "未知状态码"
                    }
                    0x0A -> when (this) {
                        0x01 -> "验证失败"
                        else -> "未知状态码"
                    }
                    else -> "未知命令码"
                }
                0x02 -> when (this and 0x7F) {
                    0x01 -> when (this) {
                        0x01 -> "从 Y-ESAM 获取随机数密文失败"
                        0x02 -> "从 Y-ESAM 获取的密文与随机数密文1不相等"
                        0x03 -> "从 Y-ESAM 获取随机数密文2失败"
                        else -> "未知状态码"
                    }
                    0x02 -> when (this) {
                        0x01 -> "Y-ESAM 认证失败"
                        0x02 -> "获取随机数失败"
                        else -> "未知状态码"
                    }
                    0x03 -> when (this) {
                        0x01 -> "从 Y-ESAM 获取密文和 MAC 失败"
                        else -> "未知状态码"
                    }
                    0x04 -> when (this) {
                        0x01 -> "数据标识不对"
                        0x02 -> "Y-ESAM 一类设参失败"
                        0x03 -> "Y-ESAM 二类设参失败"
                        0x04 -> "参数类型不对"
                        else -> "未知状态码"
                    }
                    0x05 -> when (this) {
                        0x01 -> "数据标识不对"
                        0x02 -> "数据标识 01 Y-ESAM 获取密文 + MAC 失败"
                        0x03 -> "数据标识 02 Y-ESAM 获取密文 + MAC 失败"
                        0x04 -> "数据标识 0c Y-ESAM 获取密文 + MAC 失败"
                        else -> "未知状态码"
                    }
                    0x06 -> when (this) {
                        0x04 -> "密钥状态不合法"
                        0x05 -> "打开文件目录失败或获取随机数失败或加密随机数失败"
                        else -> "未知状态码"
                    }
                    0x07 -> when (this) {
                        0x04 -> "密钥状态不合法"
                        0x05 -> "打开文件目录失败或获取随机数失败或加密随机数失败"
                        else -> "未知状态码"
                    }
                    0x08 -> when (this) {
                        0x04 -> "密钥状态不合法"
                        0x05 -> "打开文件目录失败或获取随机数失败或加密随机数失败"
                        else -> "未知状态码"
                    }
                    0x09 -> when (this) {
                        0x01 -> "从 Y-ESAM 协商失败"
                        else -> "未知状态码"
                    }
                    0x0A -> when (this) {
                        0x01 -> "从 Y-ESAM 验证失败"
                        else -> "未知状态码"
                    }
                    0x0B -> when (this) {
                        0x01 -> "安全模式字不对"
                        0x02 -> "验证保护码失败"
                        0x03 -> "Y-ESAM 二层加密失败"
                        0x04 -> "Y-ESAM 一层加密失败"
                        0x05 -> "Y-ESAM 获取随机数失败"
                        else -> "未知状态码"
                    }
                    0x0C -> when (this) {
                        0x01 -> "RESPONSE 不对"
                        0x02 -> "Y-ESAM 解密明文 + MAC 失败"
                        0x03 -> "Y-ESAM 解密密文失败"
                        0x04 -> "Y-ESAM 解密密文 + MAC 失败"
                        0x05 -> "含数据验证信息数据不对"
                        else -> "未知状态码"
                    }
                    0x0D -> when (this) {
                        0x04 -> "密钥状态不合法"
                        0x05 -> "打开文件目录失败或获取随机数失败或加密随机数失败"
                        else -> "未知状态码"
                    }
                    0x0E -> when (this) {
                        0x04 -> "Y-ESAM 验证 MAC 失败"
                        else -> "未知状态码"
                    }
                    else -> "未知命令码"
                }
                0x03 -> when (this and 0x7F) {
                    0x01 -> when (this) {
                        0x01 -> "Y-ESAM 身份认证失败"
                        else -> "未知状态码"
                    }
                    0x02 -> when (this) {
                        0x01 -> "Y-ESAM 算 MAC 失败"
                        else -> "未知状态码"
                    }
                    0x03 -> when (this) {
                        0x01 -> "Y-ESAM 解密验 MAC 失败"
                        else -> "未知状态码"
                    }
                    0x04 -> when (this) {
                        0x04 -> "数据长度不合法"
                        0xF4 -> "解密随机数失败"
                        else -> "未知状态码"
                    }
                    0x05 -> when (this) {
                        0x04 -> "数据长度不合法"
                        0xF4 -> "解密随机数失败"
                        else -> "未知状态码"
                    }
                    else -> "未知命令码"
                }
                0x04 -> when (this and 0x7F) {
                    0x01 -> when (this) {
                        0x01 -> "Y-ESAM 电子标签认证失败"
                        else -> "未知状态码"
                    }
                    0x02 -> when (this) {
                        0x01 -> "Y-ESAM 电子标签认证失败"
                        else -> "未知状态码"
                    }
                    0x03 -> when (this) {
                        0x01 -> "Y-ESAM 加密数据地址失败"
                        else -> "未知状态码"
                    }
                    0x04 -> when (this) {
                        0x01 -> "Y-ESAM 解密回读数据失败"
                        else -> "未知状态码"
                    }
                    //0x05->""  F=0x04,A=0x85 只使用通用错误码
                    //0x06->""  F=0x04,A=0x86 只使用通用错误码
                    //0x07->""  F=0x04,A=0x87 只使用通用错误码
                    //0x08->""  F=0x04,A=0x88 只使用通用错误码
                    //0x09->""  F=0x04,A=0x89 只使用通用错误码
                    //0x0A->""  F=0x04,A=0x8A 只使用通用错误码
                    else -> "未知命令码"
                }
                0x05 -> when (this and 0x7F) {
                    0x01 -> when (this) {
                        0x01 -> "Y-ESAM 生成明文数据失败"
                        0x02 -> "Y-ESAM 生成 Token1 失败"
                        else -> "未知状态码"
                    }
                    0x02 -> when (this) {
                        0x01 -> "Y-ESAM 验证 Token2 失败"
                        else -> "未知状态码"
                    }
                    0x03 -> when (this) {
                        0x05 -> "打开文件目录失败"
                        0xF4 -> "计算 MAC 错误"
                        else -> "未知状态码"
                    }
                    0x04 -> when (this) {
                        0x01 -> "Y-ESAM 解密失败"
                        else -> "未知状态码"
                    }
                    else -> "未知命令码"
                }
                0x06 -> when (this and 0x7F) {
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06 -> when (this) {
                        0x04 -> "密钥状态不合法"
                        0x05 -> "打开文件目录失败或获取随机数失败或加密随机数失败"
                        else -> "未知状态码"
                    }
                    else -> "未知命令码"
                }
                0xFE -> when (this and 0x7F) {
                    0x01 -> when (this) {
                        0x01 -> "擦ROM失败"
                        0x02 -> "信息存储失败"
                        else -> "未知状态码"
                    }
                    //0x02->""  F=0xFE,A=0x82 只使用通用错误码
                    //0x03->""  F=0xFE,A=0x83 无错误码
                    //0x04->""  F=0xFE,A=0x84 只使用通用错误码
                    else -> "未知命令码"
                }
                else -> "未知主功能标识"
            }
            return "异常响应状态码：$meaning"
        }

        /**
         * 获取命令码或响应码含义详情
         *
         * @param F 主功能标识
         */
        private fun Int.get_C_or_A_MeaningDetails(F: Int): String =
            when (F) {
                0x00 -> when (this and 0x7F) {
                    0x01 -> "本命令获取安全单元工作状态"
                    0x02 -> "本命令验证操作员的密码"
                    0x03 -> "本命令修改操作员的密码"
                    0x04 -> "将 C-ESAM 密码验证次数改为 0"
                    0x05 -> "将 C-ESAM 密码验证次数恢复"
                    0x06 -> "本命令用于安全单元初次发行"
                    0x07 -> "本命令用于配置 ESAM "
                    0x08 -> "存储关键数据"
                    0x09 -> "读取关键数据"
                    0x0A -> "往 ESAM 中透传"
                    else -> "未知命令码"
                }
                0x01 -> when (this and 0x7F) {
                    0x01 -> "从安全单元指定 ESAM 获取随机数"
                    0x02 -> "加密给定数据"
                    0x03 -> "应用层会话密钥加密数据并计算 MAC"
                    0x04 -> "应用层会话密钥验证 MAC 解密密文"
                    0x05 -> "转加密初始化"
                    0x06 -> "设置安全单元密钥使用次数"
                    0x07 -> "使用本地密钥计算传输 MAC"
                    0x08 -> "使用本地密钥验证传输 MAC"
                    0x09 -> "使用会话密钥计算传输 MAC"
                    0x0A -> "使用会话密钥验证传输 MAC"
                    else -> "未知命令码"
                }
                0x02 -> when (this and 0x7F) {
                    0x01 -> "对电能表进行红外认证"
                    0x02 -> "生成与电能表进行身份认证的密文和随机数"
                    0x03 -> "电能表控制（09、13）"
                    0x04 -> "电能表设参（09、13）"
                    0x05 -> "电能表校时（09、13）"
                    0x06 -> "电能表密钥更新（09）"
                    0x07 -> "电能表密钥更新（13）"
                    0x08 -> "电能表开户充值（09、13）"
                    0x09 -> "698 电能表会话协商"
                    0x0A -> "698 电能表会话协商验证"
                    0x0B -> "698 电能表安全数据生成\n注：未设置离线计数器时，验保护码会失败。"
                    0x0C -> "698 电能表安全传输解密"
                    0x0D -> "698 电能表抄读数据验证"
                    0x0E -> "698 电能表抄读 ESAM 参数验证"
                    else -> "未知命令码"
                }
                0x03 -> when (this and 0x7F) {
                    0x01 -> "链路层身份认证（非对称密钥协商）"
                    0x02 -> "链路层会话密钥加密计算 MAC"
                    0x03 -> "链路层会话密钥解密验证 MAC"
                    0x04 -> "链路层会话密钥计算 MAC"
                    0x05 -> "链路层会话密钥验证 MAC"
                    else -> "未知命令码"
                }
                0x04 -> when (this and 0x7F) {
                    0x01 -> "电子封印读认证生成 token1"
                    0x02 -> "电子封印读认证验证 token2"
                    0x03 -> "加密数据地址（读）"
                    0x04 -> "解密读回数据"
                    0x05 -> "电子封印写认证生成 token1"
                    0x06 -> "电子封印写认证验证 token2"
                    0x07 -> "加密数据地址（写）"
                    0x08 -> "加密写数据"
                    0x09 -> "解密执行结果"
                    0x0A -> "加密密钥更新数据"
                    else -> "未知命令码"
                }
                0x05 -> when (this and 0x7F) {
                    0x01 -> "电子标签读认证生成 token1"
                    0x02 -> "电子标签读认证验证 token2"
                    0x03 -> "电子标签 MAC 计算"
                    0x04 -> "电子标签解密"
                    else -> "未知命令码"
                }
                0x06 -> when (this and 0x7F) {
                    0x01 -> "与 W-ESAM 进行密钥协商"
                    0x02 -> "与 W-ESAM 进行密钥协商"
                    0x03 -> "会话密钥加密计算 MAC"
                    0x04 -> "会话密钥解密验证 MAC"
                    0x05 -> "会话密钥计算 MAC"
                    0x06 -> "会话密钥验证 MAC"
                    else -> "未知命令码"
                }
                0xFE -> when (this and 0x7F) {
                    0x01 -> """
                        :升级命令 1
                        :
                        :升级发起方是现场服务终端
                        :
                        :升级文件格式：
                        :|--------------------------------------------------------------------------|
                        :| 总块数 N | 检验和 | 数据长度 n1 | 数据密文 1 | ... | 数据长度 nn | 数据密文 N |
                        :|  2 字节  | 1 字节 |   2 字节   | n1 个字节  | ... |   2 字节   |  nN 个字节 |
                        :|-------------------------------------------------------------------------|
                    """.trimMargin(":")
                    0x02 -> """
                        :升级命令 2
                        :
                        :升级发起方是安全单元
                        :
                        :升级文件格式：
                        :|--------------------------------------------------------------------------|
                        :| 总块数 N | 检验和 | 数据长度 n1 | 数据密文 1 | ... | 数据长度 nn | 数据密文 N |
                        :|  2 字节  | 1 字节 |   2 字节   | n1 个字节  | ... |   2 字节   |  nN 个字节 |
                        :|-------------------------------------------------------------------------|
                    """.trimMargin(":")
                    0x03 -> """
                        :升级命令 3
                        :
                        :升级发起方是安全单元
                        :
                        :升级文件格式：
                        :|--------------------------------------------------------------------------|
                        :| 总块数 N | 检验和 | 数据长度 n1 | 数据密文 1 | ... | 数据长度 nn | 数据密文 N |
                        :|  2 字节  | 1 字节 |   2 字节   | n1 个字节  | ... |   2 字节   |  nN 个字节 |
                        :|-------------------------------------------------------------------------|
                    """.trimMargin(":")
                    0x04 -> "指定程序跳转命令"
                    else -> "未知命令码"
                }
                else -> "未知主功能标识"
            }

        /**
         * 获取命令码或响应码含义
         *
         * @param F 主功能标识
         */
        @Suppress("FunctionName")
        private fun Int.get_C_or_A_Meaning(F: Int): String {
            val meaning = when (F) {
                0x00 -> when (this and 0x7F) {
                    0x01 -> "获取安全单元信息"
                    0x02 -> "验证操作员密码"
                    0x03 -> "修改操作员密码"
                    0x04 -> "锁定安全单元"
                    0x05 -> "解锁安全单元"
                    0x06 -> "一次发行安全单元"
                    0x07 -> "二次发行安全单元"
                    0x08 -> "存储关键数据"
                    0x09 -> "读取关键数据"
                    0x0A -> "透明转发 ESAM 指令"
                    else -> "未知命令码"
                }
                0x01 -> when (this and 0x7F) {
                    0x01 -> "获取随机数"
                    0x02 -> "应用层身份认证（非对称密钥协商）"
                    0x03 -> "应用层会话密钥加密算 MAC"
                    0x04 -> "应用层会话密钥解密验 MAC"
                    0x05 -> "转加密初始化"
                    0x06 -> "设置离线计数器"
                    0x07 -> "本地密钥计算 MAC"
                    0x08 -> "本地密钥验证 MAC"
                    0x09 -> "会话密钥计算 MAC"
                    0x0A -> "会话密钥验证 MAC"
                    else -> "未知命令码"
                }
                0x02 -> when (this and 0x7F) {
                    0x01 -> "电能表红外认证（09、13）"
                    0x02 -> "电能表远程身份认证（09、13）"
                    0x03 -> "电能表控制（09、13）"
                    0x04 -> "电能表设参（09、13）"
                    0x05 -> "电能表校时（09、13）"
                    0x06 -> "电能表密钥更新（09）"
                    0x07 -> "电能表密钥更新（13）"
                    0x08 -> "电能表开户充值（09、13）"
                    0x09 -> "698 电能表会话协商"
                    0x0A -> "698 电能表会话协商验证"
                    0x0B -> "698 电能表安全数据生成"
                    0x0C -> "698 电能表安全传输解密"
                    0x0D -> "698 电能表抄读数据验证"
                    0x0E -> "698 电能表抄读 ESAM 参数验证"
                    else -> "未知命令码"
                }
                0x03 -> when (this and 0x7F) {
                    0x01 -> "链路层身份认证（非对称密钥协商）"
                    0x02 -> "链路层会话密钥加密计算 MAC"
                    0x03 -> "链路层会话密钥解密验证 MAC"
                    0x04 -> "链路层会话密钥计算 MAC"
                    0x05 -> "链路层会话密钥验证 MAC"
                    else -> "未知命令码"
                }
                0x04 -> when (this and 0x7F) {
                    0x01 -> "电子封印读认证生成 token1"
                    0x02 -> "电子封印读认证验证 token2"
                    0x03 -> "加密数据地址（读）"
                    0x04 -> "解密读回数据"
                    0x05 -> "电子封印写认证生成 token1"
                    0x06 -> "电子封印写认证验证 token2"
                    0x07 -> "加密数据地址（写）"
                    0x08 -> "加密写数据"
                    0x09 -> "解密执行结果"
                    0x0A -> "加密密钥更新数据"
                    else -> "未知命令码"
                }
                0x05 -> when (this and 0x7F) {
                    0x01 -> "电子标签读认证生成 token1"
                    0x02 -> "电子标签读认证验证 token2"
                    0x03 -> "电子标签 MAC 计算"
                    0x04 -> "电子标签解密"
                    else -> "未知命令码"
                }
                0x06 -> when (this and 0x7F) {
                    0x01 -> "外设密钥协商"
                    0x02 -> "外设密钥协商确认"
                    0x03 -> "会话密钥加密计算 MAC"
                    0x04 -> "会话密钥解密验证 MAC"
                    0x05 -> "会话密钥计算 MAC"
                    0x06 -> "会话密钥验证 MAC"
                    else -> "未知命令码"
                }
                0xFE -> when (this and 0x7F) {
                    0x01 -> "升级命令 1"
                    0x02 -> "升级命令 2"
                    0x03 -> "升级命令 3"
                    0x04 -> "指定程序跳转命令"
                    else -> "未知命令码"
                }
                else -> "未知主功能标识"
            }
//            return if(!isFE03Acknowledgement){
//                if(!isAcknoledgement)
//                    when {
//                        //安全单元升级命令的特殊情况，0x02 和 0x03 由安全单元发起
//                        F == 0xFE && (this and 0x7F) == 0x02 ||
//                                F == 0xFE && (this and 0x7F) == 0x03 -> "命令类型：${meaning};\n传输方向: 安全单元 ---> 现场服务终端"
//                        else -> "命令类型：${meaning};\n传输方向: 现场服务终端 ---> 安全单元"
//                    }
//                else
//                    when {
//                        //安全单元升级命令的特殊情况，0x82 现场服务终端返回给安全单元
//                        F == 0xFE && this  == 0x82  -> "命令类型：${meaning};\n传输方向: 现场服务终端 ---> 安全单元"
//                        else -> "命令类型：${meaning};\n传输方向: 安全单元 ---> 现场服务终端"
//                    }
//            }else{
//                //安全单元升级命令的特殊情况 0x03 的返回帧由现场服务终端返回给安全单元，且无响应码
//                "命令类型：升级命令3;\n传输方向: 现场服务终端 ---> 安全单元"
//            }
            return if (!isAcknoledgement)
                when {
                    //安全单元升级命令的特殊情况，0x02 和 0x03 由安全单元发起
                    F == 0xFE && (this and 0x7F) == 0x02 ||
                            F == 0xFE && (this and 0x7F) == 0x03 -> "命令类型：${meaning}\n传输方向: 安全单元 ---> 现场服务终端"
                    else -> "命令类型：${meaning}\n传输方向: 现场服务终端 ---> 安全单元"
                }
            else
                when {
                    //安全单元升级命令的特殊情况，0x82 现场服务终端返回给安全单元
                    F == 0xFE && this == 0x82 -> "命令类型：${meaning};\n传输方向: 现场服务终端 ---> 安全单元"
                    else -> "命令类型：${meaning};\n传输方向: 安全单元 ---> 现场服务终端"
                }
        }

        /**
         * 获取主功能标识含义
         */
        @Suppress("FunctionName")
        private fun Int.get_F_Meaning(): String =
            "主功能标识：" + when (this) {
                0x00 -> "安全单元自身操作命令"
                0x01 -> "现场服务终端与管理系统交互类命令"
                0x02 -> "现场服务终端与电能表的交互命令"
                0x03 -> "现场服务终端与安全隔离网关交互类命令"
                0x04 -> "现场服务终端与电子封印的交互命令"
                0x05 -> "现场服务终端与电子标签的交互命令"
                0x06 -> "现场服务终端与外设交互命令"
                0xFE -> when (isFE03Acknowledgement) {
                    //安全单元升级命令的特殊情况 0x03 的返回帧由现场服务终端返回给安全单元，且无响应码
                    true -> "安全单元升级命令\n命令类型：升级命令3;\n传输方向: 现场服务终端 ---> 安全单元"
                    else -> "安全单元升级命令"
                }
                else -> "未知主功能标识"
            }

        /**
         * 将当前 16 进制字符串转换为 UTF-8 编码的字符串
         */
        @ExperimentalUnsignedTypes
        private fun String.parseHexAsUTF8String(): String {
            val byteList = mutableListOf<Byte>()
            for (i in this.indices step 2) byteList.add(this.substring(i, i + 2).toUByte(16).toByte())
            return String(byteList.toByteArray(), Charset.forName("UTF-8"))
        }

        /**
         * 将当前 16 进制字符串转换为 10 进制 Int 类型数据
         */
        private fun String.parseHexAsDecInt(): Int =
            Integer.parseInt(this, 16)

        /**
         * 将当前 16 进制字符串转换为 10 进制字符串
         */
        private fun String.parseHexAsDecString(): String =
            Integer.parseInt(this, 16).toString()

        /**
         * 将当前 16 进制字符串解析为日期格式，日期格式为 yyyyMMddHHmmss 或 yyMMddHHmmss，
         * 每项都为 BCD （8421） 编码
         */
        private fun String.parseHexAsDateString(): String {
            val year = this.substring(
                0, when (this.length) {
                    14 -> 4; else -> 2
                }
            )
            val month = this.substring(4, 6)
            val day = this.substring(6, 8)
            val hour = this.substring(8, 10)
            val minute = this.substring(10, 12)
            val second = this.substring(12, 14)
            return "$year-$month-$day  $hour:$minute:$second"
        }

        /**
         * 给 16 进制字符串填充 0
         *
         * @param byteLength 目标输出字节长度
         */
        private fun String.toZeroPrefixHexString(byteLength: Int = 1): String =
            when {
                this.isEmpty() -> "00".repeat(byteLength)
                this.length % 2 != 0 -> {
                    val nowByteLength = this.length / 2
                    val prefixByteLength = byteLength - nowByteLength - 1
                    if (prefixByteLength < 0) {
                        "0$this"
                    } else {
                        val prefix = "00".repeat(prefixByteLength)
                        "${prefix}0$this"
                    }
                }
                else -> {
                    val nowByteLength = this.length / 2
                    val prefixByteLength = byteLength - nowByteLength
                    if (prefixByteLength < 0) {
                        this
                    } else {
                        val prefix = "00".repeat(prefixByteLength)
                        "$prefix$this"
                    }

                }
            }

        /**
         * 将当前数字转换为 16 进制字符串且填充 0
         *
         * @param byteLength 目标输出字节长度
         */
        private fun Int.toZeroPrefixHexString(byteLength: Int = 1): String =
            Integer.toHexString(this).toZeroPrefixHexString(byteLength)
    }


    /**
     * 安全单元帧解析结果
     */
    sealed class SecurityUnitFrameDecodeResultCode(
        val msg: String = "未知安全单元帧解析错误"
    ) {
        /**
         * 未知错误
         */
        object UNKNOW_ERROR : SecurityUnitFrameDecodeResultCode()

        /**
         * 什么都没执行
         */
        object DO_NOTHING : SecurityUnitFrameDecodeResultCode(msg = "")

        /**
         * 成功解析
         */
        object DONE : SecurityUnitFrameDecodeResultCode(msg = "安全单元帧解析完成")

        /**
         * 安全单元帧字节不完整
         */
        object FRAME_BYTE_INCOMPLETE : SecurityUnitFrameDecodeResultCode(msg = "安全单元帧字节不完整")

        /**
         * 安全单元帧不完整
         */
        object FRAME_IMCOMPLETE : SecurityUnitFrameDecodeResultCode(msg = "安全单元帧不完整")

        /**
         * 安全单元帧校验不正确
         */
        object FRAME_CHECK_FAILED : SecurityUnitFrameDecodeResultCode(msg = "安全单元帧校验不正确")
    }
}