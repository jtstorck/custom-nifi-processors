/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.processors.pcap;

import com.google.common.io.ByteStreams;
import org.apache.commons.vfs2.FileObject;
import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.FileSystemManager;
import org.apache.commons.vfs2.VFS;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.flowfile.attributes.CoreAttributes;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.exception.ProcessException;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacketHandler;

import java.io.OutputStream;

public class SplitPcap extends AbstractProcessor {


    private FileSystemManager vfsManager;

    @OnScheduled
    public void setup() {
        try {
            vfsManager = VFS.getManager();
        } catch (FileSystemException e) {
            throw new ProcessException("Could not get the VFS manager", e);
        }
    }

    @Override
    public void onTrigger(ProcessContext processContext, ProcessSession processSession) throws ProcessException {
        final FlowFile flowFile = processSession.get();

        final ComponentLog logger = getLogger();

        if (flowFile != null) {
            final String vfsFilename = String.format("ram:/%s", flowFile.getAttribute(CoreAttributes.FILENAME.key()));
            final FileObject fileObject;
            try {
                fileObject = vfsManager.resolveFile(vfsFilename);
            } catch (FileSystemException e) {
                throw new ProcessException(String.format("Unable to resolve file in VFS: %s", vfsFilename));
            }
            processSession.read(flowFile, inputStream -> {
                final OutputStream vfsOutputStream = fileObject.getContent().getOutputStream();
                ByteStreams.copy(inputStream, vfsOutputStream);
            });

            final StringBuilder errorStringBuilder = new StringBuilder();
            final Pcap pcap = Pcap.openOffline(vfsFilename, errorStringBuilder);
            if (pcap == null) {
                throw new ProcessException(String.format("Unable to open pcap %s, error: %s", vfsFilename, errorStringBuilder.toString()));
            }
            try {
                pcap.loop(-1, (PcapPacketHandler<String>) (pcapPacket, s) -> logger.info("got packet {}", new Object[]{pcapPacket.getTotalSize()}), "offline capture");
            } finally {
                pcap.close();
            }
        }
    }
}
