/**
 * 安全单元帧解析器
 *
 * @author Jarvis Semou
 */
class SecurityUnitFrameDecoder {

    companion object {
        /**
         * 解析安全单元帧
         *
         * @param frame 安全单元中帧
         * @param resultList 存放结果列表
         */
        fun decode(frame: String, resultList: MutableList<String>): SecurityUnitFrameDecodeResultCode {
            var decodeState: SecurityUnitFrameDecodeResultCode = SecurityUnitFrameDecodeResultCode.UNKNOW_ERROR
            //字符串预处理----去除空格、换行、转换为大写
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
         * 安全单元帧格式完整性检测
         * @param frame 安全单元帧
         * @return Boolean true 成功，false 失败
         */
        private fun frameFormatCheck(frame: String): Boolean {
            var decodeSuccess = false

            // 字符串字符合法
            val charList = listOf('1', '2', '3', "4", "5", "6", "7", "8", "9", "0", "A", "B", "C", "D", "E", "F")
            decodeSuccess = frame.filterNot { charList.contains(it) }.isEmpty()
            if (!decodeSuccess) return decodeSuccess

            // 安全单元帧长度至少为 7，如果是返回帧，则长度至少为 8
            val receivedFrameLength = frame.length / 2  //实际接收的帧长度
            decodeSuccess = receivedFrameLength > 8 || receivedFrameLength > 7
            if (!decodeSuccess) return decodeSuccess

            // 包含主要帧特征
            // 发送标志：E9  LH  LL  F  C  DATA  CS E6
            // 接收标志：E9  LH  LL  F  A  S  DATA  CS E6

            // 以 E9 开头、以 E6 结尾
            decodeSuccess = frame.startsWith("E9") && frame.endsWith("E6")
            if (!decodeSuccess) return decodeSuccess

            // 帧长度符合 LH LL 要（直接对比排除 E9 LH LL CS E6 等 5 个字节的帧标志之后的帧字节的数量）
            val LH = Integer.parseInt(frame.substring(2, 4), 16).shl(8)
            val LL = Integer.parseInt(frame.substring(4, 6), 16)
            val frameLegth = LH and LL
            decodeSuccess = (receivedFrameLength - 5) == frameLegth
            if (!decodeSuccess) return decodeSuccess

            // 主功能标识符有效
            val F = Integer.parseInt(frame.substring(6, 8), 16)
            decodeSuccess = (F in 0x00..0x06) || F == 0xFF
            if (!decodeSuccess) return decodeSuccess

            // 命令码/响应码有效
            var C_A = Integer.parseInt(frame.substring(8, 10), 16)
            //val isAcknoledgement=C_A and 0x80 == 0x80
            C_A = C_A and 0x7f
            decodeSuccess = C_A in 0x00..0x0E
            if (!decodeSuccess) return decodeSuccess


            //检测安全单元帧是否包含主要域
            return decodeSuccess
        }

        /**
         * 安全单元帧校验检测
         * @param frame 安全单元帧
         * @return Boolean true 成功，false 失败
         */
        fun frameCheck(frame: String): Boolean {
            var decodeSuccess = false
            // 帧校验有效
            val checkAtFrame = Integer.parseInt(frame.substring(frame.length - 4, frame.length - 2), 16)
            var realCheck = 0x00
            val loopEnd = frame.length - 6
            val addedResult = 0x00
            for (i in 0..loopEnd step 2) {
                realCheck += Integer.parseInt(frame.substring(i, i + 2), 16)
                realCheck = realCheck and 0xff
            }
            decodeSuccess = realCheck == checkAtFrame
            return decodeSuccess
        }

        /**
         * 安全单元帧解析
         * @param frame 安全单元帧
         * @param resultList 解析结果列表
         * @return SecurityUnitFrameDecodeResultCode @link{SecurityUnitFrameDecodeResultCode}
         */
        private fun frameDecode(frame: String, resultList: MutableList<String>): SecurityUnitFrameDecodeResultCode {
            var decodeResultCode = SecurityUnitFrameDecodeResultCode.DONE

            return decodeResultCode
        }
    }


    /**
     * 安全单元帧解析结果
     */
    sealed class SecurityUnitFrameDecodeResultCode(
        var msg: String = "未知安全单元帧解析错误"
    ) {
        /**
         * 未知错误
         */
        object UNKNOW_ERROR : SecurityUnitFrameDecodeResultCode()

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