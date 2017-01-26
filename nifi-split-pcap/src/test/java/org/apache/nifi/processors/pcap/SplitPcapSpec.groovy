package org.apache.nifi.processors.pcap

import org.apache.nifi.util.TestRunners
import spock.lang.Specification

class SplitPcapSpec extends Specification {
    def "test pcap transfer to vfs and split"() {
        given:
        def testRunner = new TestRunners().newTestRunner(SplitPcap)
        testRunner.enqueue(new FileInputStream('src/test/resources/captured_generated_data_73816_20170124131037.pcap'))

        when:
        testRunner.run()

        then:
        noExceptionThrown()
    }
}
