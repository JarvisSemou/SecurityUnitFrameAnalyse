@file:Suppress("LocalVariableName")

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
        private var isFE03Acknowledgement by Delegates.notNull<Boolean>()

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
                dataDomainByteLength = frameByteLength - 6
                dataDomainCharStartIndex = 12
            } else {
                dataDomainByteLength = frameByteLength - 5
                dataDomainCharStartIndex = 10
            }
            // 对 F=0xFE,C=0x03 的返回帧的数据域长度的特殊计算
            if (isFE03Acknowledgement) {
                dataDomainByteLength = frameByteLength - 4
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
            resultList.add(map_E9)
            resultList.add(map_LHLL)
            resultList.add(map_F)
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
            resultList.add(map_CS)
            resultList.add(map_E6)

            return decodeResultCode
        }

        /**
         * 解析帧数据域
         *
         * @param frame 帧
         * @param resultList 存放结果的列表
         */
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
                // 安全单元自身操作命令
//                0x0001 -> parse_0001_DataDomain(frame,resultList) // 无数据域
                0x0002 -> parse_0002_DataDomain(frame, resultList)
                0x0003 -> parse_0003_DataDomain(frame, resultList)
                0x0004 -> parse_0004_DataDomain(frame, resultList)
                0x0005 -> parse_0005_DataDomain(frame, resultList)
                0x0006 -> parse_0006_DataDomain(frame, resultList)
                0x0007 -> parse_0007_DataDomain(frame, resultList)
                0x0008 -> parse_0008_DataDomain(frame, resultList)
//                0x0009->parse_0009_DataDomain(frame,resultList)
//                0x000A->parse_000A_DataDomain(frame,resultList)
//                0x0081->parse_0081_DataDomain(frame,resultList)
//                0x0082->parse_0082_DataDomain(frame,resultList)
//                0x0083->parse_0083_DataDomain(frame,resultList)
//                0x0084->parse_0084_DataDomain(frame,resultList)
//                0x0085->parse_0085_DataDomain(frame,resultList)
//                0x0086->parse_0086_DataDomain(frame,resultList)
//                0x0087->parse_0087_DataDomain(frame,resultList)
//                0x0088->parse_0088_DataDomain(frame,resultList)
//                0x0089->parse_0089_DataDomain(frame,resultList)
//                0x008A->parse_008A_DataDomain(frame,resultList)
//                // 现场服务终端与管理系统交互类命令
//                0x0101->parse_0101_DataDomain(frame,resultList)
//                0x0102->parse_0102_DataDomain(frame,resultList)
//                0x0103->parse_0103_DataDomain(frame,resultList)
//                0x0104->parse_0104_DataDomain(frame,resultList)
//                0x0105->parse_0105_DataDomain(frame,resultList)
//                0x0106->parse_0106_DataDomain(frame,resultList)
//                0x0107->parse_0107_DataDomain(frame,resultList)
//                0x0108->parse_0108_DataDomain(frame,resultList)
//                0x0109->parse_0109_DataDomain(frame,resultList)
//                0x010A->parse_010A_DataDomain(frame,resultList)
//                0x0181->parse_0181_DataDomain(frame,resultList)
//                0x0182->parse_0182_DataDomain(frame,resultList)
//                0x0183->parse_0183_DataDomain(frame,resultList)
//                0x0184->parse_0184_DataDomain(frame,resultList)
//                0x0185->parse_0185_DataDomain(frame,resultList)
//                0x0186->parse_0186_DataDomain(frame,resultList)
//                0x0187->parse_0187_DataDomain(frame,resultList)
//                0x0188->parse_0188_DataDomain(frame,resultList)
//                0x0189->parse_0189_DataDomain(frame,resultList)
//                0x018A->parse_018A_DataDomain(frame,resultList)
//                // 现场服务终端与电能表的交互命令
//                0x0201->parse_0201_DataDomain(frame,resultList)
//                0x0202->parse_0202_DataDomain(frame,resultList)
//                0x0203->parse_0203_DataDomain(frame,resultList)
//                0x0204->parse_0204_DataDomain(frame,resultList)
//                0x0205->parse_0205_DataDomain(frame,resultList)
//                0x0206->parse_0206_DataDomain(frame,resultList)
//                0x0207->parse_0207_DataDomain(frame,resultList)
//                0x0208->parse_0208_DataDomain(frame,resultList)
//                0x0209->parse_0209_DataDomain(frame,resultList)
//                0x020A->parse_020A_DataDomain(frame,resultList)
//                0x020B->parse_020B_DataDomain(frame,resultList)
//                0x020C->parse_020C_DataDomain(frame,resultList)
//                0x020D->parse_020D_DataDomain(frame,resultList)
//                0x020E->parse_020E_DataDomain(frame,resultList)
//                0x0281->parse_0281_DataDomain(frame,resultList)
//                0x0282->parse_0282_DataDomain(frame,resultList)
//                0x0283->parse_0283_DataDomain(frame,resultList)
//                0x0284->parse_0284_DataDomain(frame,resultList)
//                0x0285->parse_0285_DataDomain(frame,resultList)
//                0x0286->parse_0286_DataDomain(frame,resultList)
//                0x0287->parse_0287_DataDomain(frame,resultList)
//                0x0288->parse_0288_DataDomain(frame,resultList)
//                0x0289->parse_0289_DataDomain(frame,resultList)
//                0x028A->parse_028A_DataDomain(frame,resultList)
//                0x028B->parse_028B_DataDomain(frame,resultList)
//                0x028C->parse_028C_DataDomain(frame,resultList)
//                0x028D->parse_028D_DataDomain(frame,resultList)
//                0x028E->parse_028E_DataDomain(frame,resultList)
//                // 现场服务终端与安全隔离网关交互类命令
//                0x0301->parse_0301_DataDomain(frame,resultList)
//                0x0302->parse_0302_DataDomain(frame,resultList)
//                0x0303->parse_0303_DataDomain(frame,resultList)
//                0x0304->parse_0304_DataDomain(frame,resultList)
//                0x0305->parse_0305_DataDomain(frame,resultList)
//                0x0381->parse_0381_DataDomain(frame,resultList)
//                0x0382->parse_0382_DataDomain(frame,resultList)
//                0x0383->parse_0383_DataDomain(frame,resultList)
//                0x0384->parse_0384_DataDomain(frame,resultList)
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

        private fun parse_0008_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = HashMap<ResultType, String>()  // 文件编号
            val map_2 = HashMap<ResultType, String>()  // 操作模式
            val map_3 = HashMap<ResultType, String>()  // 偏移地址
            val map_4 = HashMap<ResultType, String>()  // 数据长度
            val map_5 = HashMap<ResultType, String>()  // 数据内容

            val data_1_byteLength = 2
            val data_2_byteLength = 1
            val data_3_byteLength = 2
            val data_4_byteLength = 2
            val data_5_byteLength =
                dataDomainByteLength - (data_1_byteLength + data_2_byteLength + data_3_byteLength + data_4_byteLength)

            val data_2_offset = 0 + data_1_byteLength * 2
            val data_3_offset = data_2_offset + data_2_byteLength * 2
            val data_4_offset = data_3_offset + data_3_byteLength * 2
            val data_5_offset = data_4_offset + data_4_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, data_3_offset)
            val data_3 = frame.substring(data_3_offset, data_4_offset)
            val data_4 = frame.substring(data_4_offset, data_5_offset)
            val data_5 = frame.substring(data_5_offset, dataDomainCharEndIndex)

            map_1[ResultType.Origin] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Analyzed] = data_1.parseHexAsDecString()
            map_1[ResultType.Meaning] = "文件编号"
            map_1[ResultType.MeaningDetails] = """
                数据名称：文件编号
                字节数：2
                数据格式：HEX
                意义：
            """.trimIndent()

            map_2[ResultType.Origin] = data_2.toZeroPrefixHexString(data_2_byteLength)
            map_2[ResultType.Analyzed] = data_2.toZeroPrefixHexString(data_2_byteLength)
            map_2[ResultType.Meaning] = "操作模式"
            map_2[ResultType.MeaningDetails] = """
                数据名称：操作模式
                字节数：1
                数据格式：HEX
                意义：
            """.trimIndent()

            map_3[ResultType.Origin] = data_3.toZeroPrefixHexString(data_3_byteLength)
            map_3[ResultType.Analyzed] = data_3.parseHexAsDecString()
            map_3[ResultType.Meaning] = "偏移地址"
            map_3[ResultType.MeaningDetails] = """
                数据名称：偏移地址
                字节数：2
                数据格式：HEX
                意义：
            """.trimIndent()

            map_4[ResultType.Origin] = data_4.toZeroPrefixHexString(data_4_byteLength)
            map_4[ResultType.Analyzed] = data_4.parseHexAsDecString()
            map_4[ResultType.Meaning] = "数据长度"
            map_4[ResultType.MeaningDetails] = """
                数据名称：数据长度
                字节数：2
                数据格式：HEX
                意义：存储数据长度
            """.trimIndent()

            map_5[ResultType.Origin] = data_5.toZeroPrefixHexString(data_5_byteLength)
            map_5[ResultType.Analyzed] = data_5.toZeroPrefixHexString(data_5_byteLength)
            map_5[ResultType.Meaning] = "数据内容"
            map_5[ResultType.MeaningDetails] = """
                数据名称：数据内容
                字节数：$data_5_byteLength
                数据格式：HEX
                意义：数据内容
            """.trimIndent()

            resultList.add(map_1)
            resultList.add(map_2)
            resultList.add(map_3)
            resultList.add(map_4)
            resultList.add(map_5)
        }

        private fun parse_0007_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            // 0007 和 0006 的解析方式一样
            parse_0006_DataDomain(frame, resultList)
        }

        private fun parseEsamType(esamType: String) = when (esamType) {
            "01" -> "C-ESAM"
            "02" -> "Y-ESAM"
            else -> "未知类型"
        }

        private class DataOf2N(
            val byteLength: String,
            val dataContent: String
        ) {
            operator fun component1(): String = byteLength
            operator fun component2(): String = dataContent
        }

        /**
         * 拆分 2 + N 结构的字节字符串数据，前两个字节是大字节序的长度信息，余下的是数据内容
         */
        private fun parse_2_N_Data(data: String): DataOf2N {
            val data_1_byteLength = 2
            val data_2_byteLength = data.length / 2 - data_1_byteLength

            val data_2_offset = data_1_byteLength * 2

            val data_1 = data.substring(0, data_2_offset)
            val data_2 = data.substring(data_2_offset)

            return DataOf2N(
                byteLength = data_1.toZeroPrefixHexString(data_1_byteLength),
                dataContent = data_2.toZeroPrefixHexString(data_2_byteLength)
            )
        }

        private fun parse_0006_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = HashMap<ResultType, String>()    // ESAM 类型
            val map_2 = HashMap<ResultType, String>()    // 发行数据内容

            val data_1_byteLength = 1
            //val data_2_byteLength = dataDomainByteLength - 1

            val data_2_offset = 0 + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            val (data_2_1, data_2_2) = parse_2_N_Data(data_2)

            map_1[ResultType.Origin] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Analyzed] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Meaning] = "ESAM 类型：" + parseEsamType(data_2_1)
            map_1[ResultType.MeaningDetails] = """
                |数据名称：ESAM 类型
                |字节数：1
                |数据格式：HEX
                |意义：
                |   01：C-ESAM
                |   02：Y-ESAM
            """.trimMargin()

            map_2[ResultType.Origin] = """
                $data_2_1
                $data_2_2
            """.trimIndent()
            map_2[ResultType.Analyzed] = """
                发行数据内容长度：${data_2_1.parseHexAsDecInt()}
                发行数据内容：$data_2_2
            """.trimIndent()
            map_2[ResultType.Meaning] = "发行数据内容"
            map_2[ResultType.MeaningDetails] = """
                数据名称：发行数据内容
                字节数：2 + N
                数据格式：HEX
                意义：发行数据内容
            """.trimIndent()

            resultList.add(map_1)
            resultList.add(map_2)
        }

        private fun parse_0005_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = HashMap<ResultType, String>()    // 解锁数据
            //val data_1_byteLength=28
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

            map_1[ResultType.Origin] = """
                ${data_1_1.toZeroPrefixHexString(data_1_1_byteLength)}
                ${data_1_2.toZeroPrefixHexString(data_1_2_byteLength)}
                ${data_1_3.toZeroPrefixHexString(data_1_3_byteLength)}
                ${data_1_4.toZeroPrefixHexString(data_1_4_byteLength)}
            """.trimIndent()
            map_1[ResultType.Analyzed] = """
                认证数据：${data_1_1.toZeroPrefixHexString(data_1_1_byteLength)}
                密码密文：${data_1_2.toZeroPrefixHexString(data_1_2_byteLength)}
                最大密码尝试次数：${data_1_3.toZeroPrefixHexString(data_1_3_byteLength)}
                剩余密码尝试次数：${data_1_4.toZeroPrefixHexString(data_1_4_byteLength)}
            """.trimIndent()
            map_1[ResultType.Meaning] = "解锁数据"
            map_1[ResultType.MeaningDetails] = """
                |数据名称：解锁数据
                |字节数：28
                |数据格式：HEX
                |意义：
                |   认证数据（8B）
                |   密码密文（16B）
                |   最大密码尝试次数（2B）
                |   剩余密码尝试次数（2B）
            """.trimMargin()
            resultList.add(map_1)
        }

        private fun parse_0004_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            val map_1 = HashMap<ResultType, String>()    // 认证数据
            val data_1_byteLength = 8
            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
            map_1[ResultType.Origin] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Analyzed] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Meaning] = "认证数据"
            map_1[ResultType.MeaningDetails] = """
                数据名称：认证数据
                字节数：8
                数据格式：HEX
                意义：
            """.trimIndent()
            resultList.add(map_1)
        }

        private fun parse_0003_DataDomain(frame: String, resultList: MutableList<HashMap<ResultType, String>>) {
            /*
            关于操作员密码的编码处理方式请看 parse_0002_DataDomain 方法
             */
            val map_1 = HashMap<ResultType, String>()    // 旧操作员密码
            val map_2 = HashMap<ResultType, String>()       // 新操作员密码

            val data_1_byteLength = 3
            val data_2_byteLength = 3

            val data_2_offset = dataDomainCharStartIndex + data_1_byteLength * 2

            val data_1 = frame.substring(dataDomainCharStartIndex, data_2_offset)
            val data_2 = frame.substring(data_2_offset, dataDomainCharEndIndex)

            map_1[ResultType.Origin] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Analyzed] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Meaning] = "旧操作员密码"
            map_1[ResultType.MeaningDetails] = """
                数据名称：旧操作员密码
                字节数：3
                数据格式：BCD （8421）
                意义：包含 0-9 数字
            """.trimIndent()

            map_2[ResultType.Origin] = data_2.toZeroPrefixHexString(data_2_byteLength)
            map_2[ResultType.Analyzed] = data_2.toZeroPrefixHexString(data_2_byteLength)
            map_2[ResultType.Meaning] = "新操作员密码"
            map_2[ResultType.MeaningDetails] = """
                数据名称：新操作员密码
                字节数：3
                数据格式：BCD （8421）
                意义：包含 0-9 数字
            """.trimIndent()

            resultList.add(map_1)
            resultList.add(map_2)
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
            val map_1 = HashMap<ResultType, String>() // 操作员密码
            val data_1_byteLength = 3
            val data_1 = frame.substring(dataDomainCharStartIndex, dataDomainCharEndIndex)
            map_1[ResultType.Origin] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Analyzed] = data_1.toZeroPrefixHexString(data_1_byteLength)
            map_1[ResultType.Meaning] = "操作员密码"
            map_1[ResultType.MeaningDetails] = """
                数据名称：操作员密码
                字节数：3
                数据格式：BCD （8421）
                意义：包含 0-9 数字
            """.trimIndent()
            resultList.add(map_1)
        }

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
                            F == 0xFE && (this and 0x7F) == 0x03 -> "命令类型：${meaning};\n传输方向: 安全单元 ---> 现场服务终端"
                    else -> "命令类型：${meaning};\n传输方向: 现场服务终端 ---> 安全单元"
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