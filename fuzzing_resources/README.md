# Fuzzing Resources

## Commercial Fuzzers
- [Synopsis Defensics](https://www.synopsys.com/software-integrity/security-testing/fuzz-testing.html)
- [Code Intelligence](https://www.code-intelligence.com/)
- [Mayhem for Code](https://forallsecure.com/mayhem-for-code)
- [BeyondSecurity Fuzzer](https://www.beyondsecurity.com/solutions/bestorm-dynamic-application-security-testing)


## Community-supported/Open Source Fuzzers
- [GitLab Protocol Fuzzer Community Edition](https://gitlab.com/gitlab-org/security-products/protocol-fuzzer-ce)
- [Mutiny Fuzzer](https://github.com/Cisco-Talos/mutiny-fuzzer)
- [Sulley](https://github.com/OpenRCE/sulley)
- [Boofuzz](https://github.com/jtpereyda/boofuzz)
- [Radamsa](https://github.com/aoh/radamsa)
- [Zzuf](http://caca.zoy.org/wiki/zzuf)
- [OWASP Zed Attack Proxy Fuzz Add-on](https://github.com/zaproxy/zap-core-help/wiki/HelpAddonsFuzzConcepts)
- [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/)
- [Honggfuzz](http://honggfuzz.com/)

## Free Tutorials
- [Fuzzing with AFL - by Michael Macnair](https://www.youtube.com/watch?v=6YLz9IGAGLw&t=3752s)
- [Attacking Antivirus Software's Kernel Driver](https://github.com/bee13oy/AV_Kernel_Vulns/tree/master/Zer0Con2017)
- [Fuzzing the Windows Kernel - OffensiveCon 2020](https://github.com/yoava333/presentations/blob/master/Fuzzing%20the%20Windows%20Kernel%20-%20OffensiveCon%202020.pdf)
- [Youtube Playlist of various fuzzing talks and presentations ](https://www.youtube.com/playlist?list=PLtPrYlwXDImiO_hzK7npBi4eKQQBgygLD)
- [DerbyCon 2016: Fuzzing basics...or how to break software](http://www.irongeek.com/i.php?page=videos/derbycon6/411-fuzzing-basicshow-to-break-software-grid-aka-scott-m)
- [TALOS Munity Fuzzer Tutorial](https://www.youtube.com/watch?v=FZyR6MgJCUs)
- [A curated list of Fuzz-related topics](https://github.com/secfigo/Awesome-Fuzzing) maintained by [@secfigo](https://twitter.com/secfigo).  Includes tools, books, free and paid courses, videos, and tutorials.

## Types of Fuzzing Techniques
The following are the most common types of fuzzing categories:

### Mutation
Mutation-based fuzzers use samples of valid input that are mutated randomly to produce malformed input. A dumb mutation fuzzer can simply select a valid sample input and alter parts of it randomly.  You can build in greater intelligence by allowing the fuzzer to do some level of parsing of the samples to ensure it only modifies specific parts or doesn’t break the overall structure of the input so it’s immediately rejected by the program. Some protocols or file formats will incorporate checksums that will fail if they’re modified arbitrarily. A mutation-based fuzzer should usually fix these checksums so the input’s accepted for processing or the only code tested is the checksum validation and nothing else.

### Generation
Generation-based fuzzers actually generate input from scratch rather than mutating existing input. They usually require some level of intelligence to construct input that makes at least some sense to the program, although generating completely random data would also technically be generation. Generation fuzzers often split a protocol or file format into chunks, which they can build up in a valid order, and randomly fuzz some of those chunks independently. This can create inputs that preserve their overall structure, but contain inconsistent data within it. The granularity of these chunks and the intelligence with which they’re constructed define the level of intelligence of the fuzzer. While mutation-based fuzzing can have a similar effect as generation fuzzing (as, over time, mutations will be randomly applied without completely breaking the input’s structure), generating inputs ensures this will be so. Generation fuzzing can also get deeper into a protocol more easily, as it can construct valid sequences of inputs applying fuzzing to specific parts of that communication. It also allows the fuzzer to act as a true client/server, generating correct, dynamic responses where these can’t be blindly replayed.

### Evolutionary
Evolutionary fuzzing’s an advanced technique. It allows the fuzzer to use feedback from each test case to learn the format of the input over time. 
