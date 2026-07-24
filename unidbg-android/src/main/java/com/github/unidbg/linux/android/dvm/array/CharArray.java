package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;

public class CharArray extends BaseArray<char[]> implements PrimitiveArray<char[]> {

    public CharArray(VM vm, char[] value) {
        super(vm.resolveClass("[C"), value);
    }

    @Override
    public int length() {
        return value.length;
    }

    public void setValue(char[] value) {
        super.value = value;
    }

    @Override
    public void setData(int start, char[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }

    @Override
    public UnidbgPointer _GetArrayCritical(Emulator<?> emulator, Pointer isCopy) {
        if (isCopy != null) {
            isCopy.setInt(0, VM.JNI_TRUE);
        }
        int len = value.length;
        ByteBuffer bb = ByteBuffer.allocate(len * 2);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        CharBuffer cb = bb.asCharBuffer();
        cb.put(value);
        byte[] bytes = bb.array();
        UnidbgPointer pointer = this.allocateMemoryBlock(emulator, bytes.length);
        pointer.write(0, bytes, 0, bytes.length);
        return pointer;
    }

    @Override
    public void _ReleaseArrayCritical(Pointer elems, int mode) {
        switch (mode) {
            case VM.JNI_COMMIT: {
                int len = value.length;
                byte[] bytes = elems.getByteArray(0, len * 2);
                ByteBuffer bb = ByteBuffer.wrap(bytes);
                bb.order(ByteOrder.LITTLE_ENDIAN);
                CharBuffer cb = bb.asCharBuffer();
                char[] chars = new char[len];
                cb.get(chars);
                this.setValue(chars);
                break;
            }
            case 0: {
                int len = value.length;
                byte[] bytes = elems.getByteArray(0, len * 2);
                ByteBuffer bb = ByteBuffer.wrap(bytes);
                bb.order(ByteOrder.LITTLE_ENDIAN);
                CharBuffer cb = bb.asCharBuffer();
                char[] chars = new char[len];
                cb.get(chars);
                this.setValue(chars);
            }
            case VM.JNI_ABORT:
                this.freeMemoryBlock(elems);
                break;
        }
    }
}
