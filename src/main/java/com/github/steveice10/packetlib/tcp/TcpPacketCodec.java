package com.github.steveice10.packetlib.tcp;

import com.github.steveice10.packetlib.Session;
import com.github.steveice10.packetlib.event.session.PacketErrorEvent;
import com.github.steveice10.packetlib.io.NetInput;
import com.github.steveice10.packetlib.io.NetOutput;
import com.github.steveice10.packetlib.packet.Packet;
import com.github.steveice10.packetlib.packet.PacketProtocol;
import com.github.steveice10.packetlib.tcp.io.ByteBufNetInput;
import com.github.steveice10.packetlib.tcp.io.ByteBufNetOutput;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageCodec;

import java.util.List;

public class TcpPacketCodec extends ByteToMessageCodec<Packet> {
    private Session session;

    public TcpPacketCodec(Session session) {
        this.session = session;
    }

    @Override
    public void encode(ChannelHandlerContext ctx, Packet packet, ByteBuf buf) throws Exception {
        int initial = buf.writerIndex();

        try {
            NetOutput out = new ByteBufNetOutput(buf);

            this.session.getPacketProtocol().getPacketHeader().writePacketId(out, this.session.getPacketProtocol().getOutgoingId(packet));
            packet.write(out);
        } catch(Throwable t) {
            // Reset writer index to make sure incomplete data is not written out.
            buf.writerIndex(initial);

            PacketErrorEvent e = new PacketErrorEvent(this.session, t);
            this.session.callEvent(e);
            if(!e.shouldSuppress()) {
                throw t;
            }
        }
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf buf, List<Object> out) throws Exception {
        int initial = buf.readerIndex();

        try {
            NetInput in = new ByteBufNetInput(buf);

            final PacketProtocol packetProtocol = this.session.getPacketProtocol();

            int id = packetProtocol.getPacketHeader().readPacketId(in);
            if(id == -1) {
                buf.readerIndex(initial);
                return;
            }

            if (id == 0x53 /* player list packet */ ||
                    id == 0x20 /* chunk data packet */ ||
                    id == 0x23 /* light packet */ ||
                    id == 0x44 /* entity meta packet */ ||
                    id == 0x32 /* player info packet */) {
                buf.readerIndex(buf.readerIndex() + buf.readableBytes());
                return;
            }

            Packet packet = packetProtocol.createIncomingPacket(id);
            packet.read(in);

            if(buf.readableBytes() > 0) {
                throw new IllegalStateException("Packet \"" + packet.getClass().getSimpleName() + "\" not fully read.");
            }

            out.add(packet);
        } catch(Throwable t) {
            System.out.println("error");
            // Advance buffer to end to make sure remaining data in this packet is skipped.
            buf.readerIndex(buf.readerIndex() + buf.readableBytes());

            PacketErrorEvent e = new PacketErrorEvent(this.session, t);
            this.session.callEvent(e);
            if(!e.shouldSuppress()) {
                throw t;
            }
        }
    }
}
