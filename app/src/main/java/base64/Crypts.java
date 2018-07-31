package base64;

import java.io.IOException;

public class Crypts {
	static int ENC_16[] = { 5, 4, 14, 6, 2, 1, 8, 12, 15, 0, 11, 9, 10, 7, 13,
			3 };
	static int DEC_16[] = { 9, 5, 4, 15, 1, 0, 3, 13, 6, 11, 12, 10, 7, 14, 2,
			8 };

	public static BASE64Encoder b64encoder = new BASE64Encoder();
	public static BASE64Decoder b64decoder = new BASE64Decoder();

	static char[] byteToChar(byte[] src) {
		char[] dst = new char[src.length];
		for (int i = 0; i < src.length; i++) {
			int nVal = src[i];
			if (nVal < 0)
				nVal += 0x100;
			dst[i] = (char) nVal;
		}
		return dst;
	}

	static byte[] charToByte(char[] src) {
		byte[] dst = new byte[src.length];
		for (int i = 0; i < src.length; i++)
			dst[i] = (byte) src[i];
		return dst;
	}

	public static String xorMapEncrypt(int key, String ss) throws IOException {
		char[] srcBytes = byteToChar(ss.getBytes("utf-8"));
		char[] dstBytes = new char[srcBytes.length + 1];

		int keyBt = key % 0x100;
		dstBytes[srcBytes.length] = (char) (byte) keyBt;
		// System.out.println(keyBt);
		for (int j = 0; j < srcBytes.length; j++) {
			int b1 = srcBytes[j];
			int b2 = (b1 ^ keyBt) & 0xff;
			int c1 = b2 % 16;
			int c2 = b2 / 16;
			c1 = ENC_16[c1];
			c2 = ENC_16[c2];

			int b3 = c2 * 16 + c1;
			dstBytes[j] = (char) b3;
		}
		// System.out.println(dstBytes.length);
		String isoString = b64encoder.encode(charToByte(dstBytes));
		return isoString;
	}

	public static String xorMapDecrypt(String ss) throws IOException {

		char[] srcBytes = byteToChar(b64decoder.decodeBuffer(ss));
		if (srcBytes.length < 1)
			return "";

		// System.out.println(srcBytes.length);

		char[] dstBytes = new char[srcBytes.length - 1];
		int keyBt = (int) srcBytes[dstBytes.length];
		// System.out.println(keyBt);
		if (keyBt < 0)
			keyBt += 0x100;
		for (int j = 0; j < dstBytes.length; j++) {
			int b1 = srcBytes[j];
			int c1 = b1 % 16;
			int c2 = b1 / 16;
			c1 = DEC_16[c1];
			c2 = DEC_16[c2];

			int b3 = c2 * 16 + c1;
			int b2 = (b3 ^ keyBt) & 0xff;
			dstBytes[j] = (char) b2;
		}
		return new String(charToByte(dstBytes), "utf-8");
	}

}
