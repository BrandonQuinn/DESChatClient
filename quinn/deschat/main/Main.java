package quinn.deschat.main;

import quinn.deschat.encryption.DES;

public class Main {
	public static void main(String args[]) {
		DES des = new DES();
		byte[] key = des.generateKey();
		byte[] cipher = des.encrypt("This is a crazy message", key);
	}
}
