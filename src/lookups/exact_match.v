///////////////////////////////////////////////////////////////////////////////
// $Id: exact_match.v 3647 2008-04-23 02:29:18Z jnaous $
//
// Module: exact_match.v
// Project: NF2.1 OpenFlow Switch
// Author: Jad Naous <jnaous@stanford.edu>
// Description: matches an exact flow entry using two hash functions. Uses the
//              SRAM to store the flow table including counters.
//              CAUTION: This module's state machine is TIGHTLY coupled with that
//              of the SRAM arbiter used. So make sure to modify both at the same
//              time
//
// Licensing: In addition to the NetFPGA license, the following license applies
//            to the source code in the OpenFlow Switch implementation on NetFPGA.
//
// Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
//
// We are making the OpenFlow specification and associated documentation (Software)
// available for public use and benefit with the expectation that others will use,
// modify and enhance the Software and contribute those enhancements back to the
// community. However, since we would like to make the Software available for
// broadest use, with as few restrictions as possible permission is hereby granted,
// free of charge, to any person obtaining a copy of this Software to deal in the
// Software under the copyrights without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// The name and trademarks of copyright holder(s) may NOT be used in advertising
// or publicity pertaining to the Software or any derivatives without specific,
// written prior permission.
///////////////////////////////////////////////////////////////////////////////


  module exact_match
    #(parameter NUM_OUTPUT_QUEUES = 8,                  // obvious
      parameter PKT_SIZE_WIDTH = 12,                    // number of bits for pkt size
      parameter SRAM_ADDR_WIDTH = 19,
      parameter DATA_WIDTH = 64,
      parameter CTRL_WIDTH = DATA_WIDTH/8
      )
   (// --- Interface for lookups
    input [`OPENFLOW_ENTRY_WIDTH-1:0]       flow_entry, // OPENFLOW_ENTRY_WIDTH = 248
    input                                   flow_entry_vld,
    input [PKT_SIZE_WIDTH-1:0]              pkt_size,
    output                                  exact_match_rdy,

    // --- Interface to arbiter
    output reg                              exact_hit,
    output reg                              exact_miss,
    output reg [`OPENFLOW_ACTION_WIDTH-1:0] exact_data, // OPENFLOW_ACTION_WIDTH = 320
    output reg                              exact_data_vld,
    input                                   exact_wins,
    input                                   exact_loses,

    // --- SRAM Interface
    output [SRAM_ADDR_WIDTH-1:0]            wr_0_addr,
    output reg                              wr_0_req,
    input                                   wr_0_ack,
    output reg [DATA_WIDTH+CTRL_WIDTH-1:0]  wr_0_data,

    input                                   rd_0_ack,
    input  [DATA_WIDTH+CTRL_WIDTH-1:0]      rd_0_data,
    input                                   rd_0_vld,
    output [SRAM_ADDR_WIDTH-1:0]            rd_0_addr,
    output reg                              rd_0_req,

    // --- Misc
    input [31:0]                            openflow_timer,
    input                                   reset,
    input                                   clk
   );

   `LOG2_FUNC
   `CEILDIV_FUNC

   //-------------------- Internal Parameters ------------------------
   localparam EXACT_NUM_ACTION_WORDS_USED = ceildiv(`OPENFLOW_ACTION_WIDTH, DATA_WIDTH);
   localparam EXACT_NUM_FLOW_WORDS_USED = ceildiv(`OPENFLOW_ENTRY_WIDTH, DATA_WIDTH);

   // each entry uses 16 mem locations
   localparam ENTRY_ADDR_WIDTH = SRAM_ADDR_WIDTH - 4;

   //---------------------- Wires and regs----------------------------
   wire [PKT_SIZE_WIDTH-1:0]                         dout_pkt_size;
   wire [`OPENFLOW_ENTRY_WIDTH-1:0]                  dout_flow_entry;
   wire [ENTRY_ADDR_WIDTH-1:0]                       flow_index_0;
   wire [ENTRY_ADDR_WIDTH-1:0]                       flow_index_1;

   reg [4:0]                                         cycle_num;
   reg [`OPENFLOW_ENTRY_WIDTH-1:0]                   flow_0_hdr;
   reg [PKT_SIZE_WIDTH-1:0]                          flow_0_pkt_size;
   reg [`OPENFLOW_ENTRY_WIDTH-1:0]                   flow_1_hdr;
   reg [PKT_SIZE_WIDTH-1:0]                          flow_1_pkt_size;
   reg                                               fifo_rd_en;
   reg                                               flow_0_vld;
   reg                                               flow_1_vld;
   reg [ENTRY_ADDR_WIDTH-1:0]                        flow_0_index_0;
   reg [ENTRY_ADDR_WIDTH-1:0]                        flow_0_index_1;
   reg [ENTRY_ADDR_WIDTH-1:0]                        flow_1_index_0;
   reg [ENTRY_ADDR_WIDTH-1:0]                        flow_1_index_1;
   reg [SRAM_ADDR_WIDTH-1:0]                         addr;
   reg                                               flow_0_index_0_match;
   reg                                               flow_0_index_1_match;
   reg                                               flow_1_index_0_match;
   reg                                               flow_1_index_1_match;
   reg [DATA_WIDTH-1:0]                              flow_0_cntrs;
   reg [DATA_WIDTH-1:0]                              flow_1_cntrs;

   wire [`OPENFLOW_EXACT_ENTRY_PKT_COUNTER_WIDTH-1:0]      flow_0_pkt_cntr;
   wire [`OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_WIDTH-1:0]     flow_0_byte_cntr;
   wire [`OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH-1:0]        flow_0_last_seen;
   wire [DATA_WIDTH-1:0]                                   flow_0_cntrs_updated;

   wire [`OPENFLOW_EXACT_ENTRY_PKT_COUNTER_WIDTH-1:0]      flow_1_pkt_cntr;
   wire [`OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_WIDTH-1:0]     flow_1_byte_cntr;
   wire [`OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH-1:0]        flow_1_last_seen;
   wire [DATA_WIDTH-1:0]                                   flow_1_cntrs_updated;

   //------------------------- Modules -------------------------------

   fallthrough_small_fifo
     #(.WIDTH(`OPENFLOW_ENTRY_WIDTH + PKT_SIZE_WIDTH),
       .MAX_DEPTH_BITS(2))
      flow_entry_fifo_0
        (.din           ({pkt_size, flow_entry}),     // Data in
         .wr_en         (flow_entry_vld),             // Write enable
         .rd_en         (fifo_rd_en),                 // Read the next word
         .dout          ({dout_pkt_size, dout_flow_entry}),
         .full          (),
         .nearly_full   (),
         .empty         (flow_fifo_empty),
         .reset         (reset),
         .clk           (clk)
         );

   header_hash
     #(.INPUT_WIDTH   (`OPENFLOW_ENTRY_WIDTH),
       .OUTPUT_WIDTH  (ENTRY_ADDR_WIDTH))
       header_hash
         (.data              (dout_flow_entry),
          .hash_0            (flow_index_0),
          .hash_1            (flow_index_1),
          .clk               (clk),
          .reset             (reset));

   //-------------------------- Logic --------------------------------
   assign exact_match_rdy    = 1'b1;
   assign rd_0_addr          = addr;
   assign wr_0_addr          = addr;
   assign flow_0_pkt_cntr    = flow_0_cntrs[`OPENFLOW_EXACT_ENTRY_PKT_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_PKT_COUNTER_WIDTH];
   assign flow_0_byte_cntr   = flow_0_cntrs[`OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_WIDTH];
   assign flow_0_last_seen   = flow_0_cntrs[`OPENFLOW_EXACT_ENTRY_LAST_SEEN_POS +: `OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH];
   assign flow_1_pkt_cntr    = flow_1_cntrs[`OPENFLOW_EXACT_ENTRY_PKT_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_PKT_COUNTER_WIDTH];
   assign flow_1_byte_cntr   = flow_1_cntrs[`OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_WIDTH];
   assign flow_1_last_seen   = flow_1_cntrs[`OPENFLOW_EXACT_ENTRY_LAST_SEEN_POS +: `OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH];
   assign flow_0_cntrs_updated[`OPENFLOW_EXACT_ENTRY_PKT_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_PKT_COUNTER_WIDTH]   = flow_0_pkt_cntr + 1'b1;
   assign flow_0_cntrs_updated[`OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_WIDTH] = flow_0_byte_cntr + flow_0_pkt_size;
   assign flow_0_cntrs_updated[`OPENFLOW_EXACT_ENTRY_LAST_SEEN_POS +: `OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH]       = openflow_timer[`OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH-1:0];
   assign flow_1_cntrs_updated[`OPENFLOW_EXACT_ENTRY_PKT_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_PKT_COUNTER_WIDTH]   = flow_1_pkt_cntr + 1'b1;
   assign flow_1_cntrs_updated[`OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_POS +: `OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_WIDTH] = flow_1_byte_cntr + flow_1_pkt_size;
   assign flow_1_cntrs_updated[`OPENFLOW_EXACT_ENTRY_LAST_SEEN_POS +: `OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH]       = openflow_timer[`OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH-1:0];

   /* This state machine issues the reads and writes to the SRAM,
    * handles the results and checks for matches.
    * The state machine looksup two flow simulataneously in the SRAM
    * to maximize throughput. In the first 8 cycles (starting at cycle_num 2),
    * the two hash entries (hash0 and hash1) in the SRAM for this flow header (flow_0) are checked.
    * Each check is 4 cycles for a total of 8 cycles. Then a new flow entry
    * header (flow_1) is read if one is available, and its two hash entries are checked
    * for a match. By this time, the result of the matching of flow 0 is known,
    * and we start reading the counters (1 word) and the actions (5 words) for
    * flow 0 from the correct location. If we had a hit, then we update the counters
    * (1 more cycle). By the time this is done, the result of
    * the matching for flow 1 is known, and we start doing the same for flow 1.
    *
    * Note that the exact_hit/miss and exact_data_vld are separate, but follow
    * each other. i.e. we'll get the exact_hit/miss then the exact_data_vld for
    * flow 0 and then the exact_hit/miss then the exact_data_vld for flow 1. This
    * simplifies the job of the arbiter. */
   always @(posedge clk) begin
      if (reset) begin
         cycle_num               <= 0;
         fifo_rd_en              <= 0;
         wr_0_req                <= 0;
         addr                    <= 0;
         rd_0_req                <= 1'b0;
         exact_data_vld          <= 1'b0;
         exact_hit               <= 0;
         exact_miss              <= 0;
         flow_0_vld              <= 1'b0;
         flow_1_vld              <= 1'b0;
         flow_0_index_0_match    <= 1'b0;     flow_0_index_1_match    <= 1'b0;
    
         flow_1_index_0_match    <= 1'b0;
         flow_1_index_1_match    <= 1'b0;
      end
      else begin
         // defaults
         cycle_num         <= (cycle_num == 1 && !rd_0_ack) ? 1 : cycle_num + 1'b1;
         fifo_rd_en        <= 0;
         wr_0_req          <= 0;
         wr_0_data         <= flow_0_cntrs_updated;
         addr              <= addr + 1'b1;
         rd_0_req          <= 1'b0;
         exact_data_vld    <= 1'b0;
         exact_hit         <= 0;
         exact_miss        <= 0;

         case (cycle_num)
            /*
             * 1- read flow 1 action word 4
             * 2- latch flow 1 counters
             */
            0: begin
               rd_0_req        <= 1'b1;

               flow_1_cntrs    <= rd_0_data;
            end

            /*
             * 1- Write back updated counters for flow 1
             * 2- latch action flow 1 word 1
             * 3- read new flow entry for flow 0 if existing
             */
            1: begin
               /* write back updated counters for flow 1 */
               addr <= EXACT_NUM_FLOW_WORDS_USED + (flow_1_index_0_match
                                                    ? {flow_1_index_0, 4'h0}
                                                    : {flow_1_index_1, 4'h0});
               wr_0_req                                 <= flow_1_vld && exact_wins;
               wr_0_data                                <= flow_1_cntrs_updated;

               /* read flow 0 */
               flow_0_hdr         <= dout_flow_entry;
               flow_0_pkt_size    <= dout_pkt_size;
               if(!flow_fifo_empty) begin
                  fifo_rd_en    <= 1;
                  flow_0_vld    <= 1'b1;
               end

               /* latch exact data for flow 1 */
               exact_data[DATA_WIDTH-1:0]    <= rd_0_data;
            end

            /*
             * 1- set the sram address to read header word 0 from hash0 flow 0
             * 2- latch action flow 1 word 1
             */
            2: begin
               flow_0_index_0                           <= flow_index_0;
               flow_0_index_1                           <= flow_index_1;
               addr                                     <= {flow_index_0, 4'h0};
               rd_0_req                                 <= 1'b1;

               exact_data[2*DATA_WIDTH-1:DATA_WIDTH]    <= rd_0_data;
            end

            /*
             * 1- read header word 1 from hash0 flow 0
             * 2- latch action flow 1 word 2
             */
            3: begin
               rd_0_req                                   <= 1'b1;
               exact_data[3*DATA_WIDTH-1:2*DATA_WIDTH]    <= rd_0_data;
            end

            /*
             * 1- read header word 2 from hash0 flow 0
             * 2- latch action flow 1 word 3
             */
            4: begin
               rd_0_req          <= 1'b1;
               exact_data[4*DATA_WIDTH-1:3*DATA_WIDTH]    <= rd_0_data;
            end

            /*
             * 1- read header word 3 from hash0 flow 0
             * 2- latch action flow 1 word 4
             * 3- Set exact data vld since we've read all action words for flow 1 and reset flow 1 control signals
             */
            5: begin
               rd_0_req          <= 1'b1;

               exact_data[5*DATA_WIDTH-1:4*DATA_WIDTH]    <= rd_0_data;
               exact_data_vld    <= flow_1_vld;
               flow_1_vld        <= 0;
            end

            /*
             * 1- read header word 0 from hash1 flow 0
             * 2- 5 cycles ago was was one the SRAM would reset counters on read so no
             *    vld rd data this cycle
             */
            6: begin
               addr        <= {flow_0_index_1, 4'h0};
               rd_0_req    <= 1'b1;

               // synthesis translate_off
               if (rd_0_vld) begin
                  $display("%t %m ERROR: Cycle 6 There should be no rd_0_vld since cntrs were written to SRAM, no rd req.", $time);
                  $stop;
               end
               // synthesis translate_on
            end

            /*
             * 1- read header word 1 from hash1 flow 0
             * 2- Check if word 0 from hash0 matches word 0 of flow header 0
             */
            7: begin
               rd_0_req                <= 1'b1;
               flow_0_index_0_match    <= (flow_0_hdr[DATA_WIDTH-1:0]
                                            === rd_0_data[DATA_WIDTH-1:0]);
            end

            /*
             * 1- read header word 2 from hash1 flow 0
             * 2- Check if word 1 from hash0 matches word 1 of flow header
             */
            8: begin
               rd_0_req                <= 1'b1;
               flow_0_index_0_match    <= ((flow_0_hdr[2*DATA_WIDTH-1:DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_0_index_0_match);
            end

            /*
             * 1- read header word 3 from hash1 flow 0
             * 2- Check if word 2 from hash0 matches word 2 of flow header 0
             * 3- if there's a new flow header (flow_1) then latch it and rd the fifo
             */
            9: begin
               rd_0_req                <= 1'b1;
               flow_0_index_0_match    <= ((flow_0_hdr[3*DATA_WIDTH-1:2*DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_0_index_0_match);

               flow_1_hdr         <= dout_flow_entry;
               flow_1_pkt_size    <= dout_pkt_size;
               if(!flow_fifo_empty) begin
                  fifo_rd_en    <= 1;
                  flow_1_vld    <= 1'b1;
               end
            end

            /*
             * 1- read header word 0 from hash0 flow 1
             * 2- Check if word 3 from hash0 matches word 3 of flow header 0
             *    along with the valid bit (MSbit)
             */
            10: begin
               flow_1_index_0    <= flow_index_0;
               flow_1_index_1    <= flow_index_1;
               addr              <= {flow_index_0, 4'h0};
               rd_0_req                <= 1'b1;
               flow_0_index_0_match    <= (({1'b1,{(4*DATA_WIDTH-`OPENFLOW_ENTRY_WIDTH-1){1'b0}}, flow_0_hdr[`OPENFLOW_ENTRY_WIDTH-1:3*DATA_WIDTH]}
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_0_index_0_match);
            end

            /*
             * 1- read header word 1 from hash0 flow 1
             * 2- Check if word 0 from hash1 matches word 0 of flow header 0
             */
            11: begin
               rd_0_req                <= 1'b1;
               flow_0_index_1_match    <= (flow_0_hdr[DATA_WIDTH-1:0]
                                           === rd_0_data[DATA_WIDTH-1:0]);
            end

            /*
             * 1- read header word 2 from hash0 flow 1
             * 2- Check if word 1 from hash1 matches word 1 of flow header 0
             */
            12: begin
               rd_0_req                <= 1'b1;
               flow_0_index_1_match    <= ((flow_0_hdr[2*DATA_WIDTH-1:DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_0_index_1_match);
            end

            /*
             * 1- read header word 3 from hash0 flow 1
             * 2- Check if word 2 from hash1 matches word 2 of flow header 0
             */
            13: begin
               rd_0_req                <= 1'b1;
               flow_0_index_1_match    <= ((flow_0_hdr[3*DATA_WIDTH-1:2*DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_0_index_1_match);

            end

            /*
             * 1- read header word 0 from hash1 flow 1
             * 2- Check if word 3 from hash1 matches word 3 of flow header 0
             */
            14: begin
               addr                    <= {flow_1_index_1, 4'h0};
               rd_0_req                <= 1'b1;
               flow_0_index_1_match    <= (({1'b1,{(4*DATA_WIDTH-`OPENFLOW_ENTRY_WIDTH-1){1'b0}}, flow_0_hdr[`OPENFLOW_ENTRY_WIDTH-1:3*DATA_WIDTH]}
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_0_index_1_match);
            end

            /*
             * 1- read header word 1 from hash1 flow 1
             * 2- Check if word 0 from hash0 matches word 0 of flow header 1
             */
            15: begin
               rd_0_req                <= 1'b1;
               flow_1_index_0_match    <= (flow_1_hdr[DATA_WIDTH-1:0]
                                           === rd_0_data[DATA_WIDTH-1:0]);
            end

            /*
             * 1- read header word 2 from hash1 flow 1
             * 2- Check if word 1 from hash0 matches word 1 of flow header 1
             */
            16: begin
               rd_0_req                <= 1'b1;
               flow_1_index_0_match    <= ((flow_1_hdr[2*DATA_WIDTH-1:DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_1_index_0_match);
            end

            /*
             * 1- read header word 3 from hash1 flow 1
             * 2- Check if word 2 from hash0 matches word 2 of flow header 1
             */
            17: begin
               rd_0_req                <= 1'b1;
               flow_1_index_0_match    <= ((flow_1_hdr[3*DATA_WIDTH-1:2*DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_1_index_0_match);
            end

            /*
             * 1- By now we now know which hash matches for flow 0, so read
             *    the counters for flow 0.
             * 2- Check if word 3 from hash0 matches word 3 of flow header 1
             *    along with the vld bit (in the MSbit)
             */
            18: begin
               /* select the address for flow 0 */
               addr <= EXACT_NUM_FLOW_WORDS_USED + (flow_0_index_0_match
                                                    ? {flow_0_index_0, 4'h0}
                                                    : {flow_0_index_1, 4'h0});
               rd_0_req                <= 1'b1;

               flow_1_index_0_match    <= (({1'b1,{(4*DATA_WIDTH-`OPENFLOW_ENTRY_WIDTH-1){1'b0}}, flow_1_hdr[`OPENFLOW_ENTRY_WIDTH-1:3*DATA_WIDTH]}
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_1_index_0_match);
            end

            /*
             * 1- read action word 0 flow 0.
             * 2- Check if word 0 from hash1 matches word 0 of flow header 1
             */
            19: begin
               rd_0_req                <= 1'b1;
               flow_1_index_1_match    <= (flow_1_hdr[DATA_WIDTH-1:0]
                                            === rd_0_data[DATA_WIDTH-1:0]);
            end

            /*
             * 1- read action word 1 flow 0.
             * 2- Check if word 1 from hash1 matches word 1 of flow header 1
             */
            20: begin
               rd_0_req                <= 1'b1;
               flow_1_index_1_match    <= ((flow_1_hdr[2*DATA_WIDTH-1:DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_1_index_1_match);
            end

            /*
             * 1- read action word 2 flow 0.
             * 2- Check if word 2 from hash1 matches word 2 of flow header 1
             */
            21: begin
               rd_0_req                <= 1'b1;
               flow_1_index_1_match    <= ((flow_1_hdr[3*DATA_WIDTH-1:2*DATA_WIDTH]
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_1_index_1_match);
            end

            /*
             * 1- read action word 3 flow 0.
             * 2- Check if word 3 from hash1 matches word 3 of flow header 1
             *    along with the vld bit
             * 3- Set the exact miss/hit
             */
            22: begin
               rd_0_req                      <= 1'b1;
               flow_1_index_1_match    <= (({1'b1,{(4*DATA_WIDTH-`OPENFLOW_ENTRY_WIDTH-1){1'b0}}, flow_1_hdr[`OPENFLOW_ENTRY_WIDTH-1:3*DATA_WIDTH]}
                                            === rd_0_data[DATA_WIDTH-1:0])
                                           && flow_1_index_1_match);

               /* set the hit/miss for flow 0 */
               exact_hit       <= (flow_0_index_0_match===1'b1 || flow_0_index_1_match===1'b1) && flow_0_vld;
               exact_miss      <= !(flow_0_index_0_match===1'b1 || flow_0_index_1_match===1'b1) && flow_0_vld;
            end

            /*
             * 1- read action word 4 flow 0.
             * 2- latch counters for flow 0
             */
            23: begin
               rd_0_req        <= 1'b1;

               flow_0_cntrs    <= rd_0_data;
            end

            /*
             * 1- Write the updated counters if we win the arbitration
             * 2- latch action word 0 flow 0
             */
            24: begin
               addr         <= EXACT_NUM_FLOW_WORDS_USED + (flow_0_index_0_match
                                                            ? {flow_0_index_0, 4'h0}
                                                            : {flow_0_index_1, 4'h0});
               wr_0_req                      <= flow_0_vld && exact_wins;
               wr_0_data                     <= flow_0_cntrs_updated;

               exact_data[DATA_WIDTH-1:0]    <= rd_0_data;
            end

            /*
             * 1- The SRAM services a register request in this cycle
             * 2- latch action word 1 flow 0
             */
            25: begin
               exact_data[2*DATA_WIDTH-1:DATA_WIDTH]    <= rd_0_data;
            end

            /*
             * 1- In this cycle, the the SRAM arbiters might reset counters
             * 2- latch action word 2 flow 0
             */
            26: begin
               exact_data[3*DATA_WIDTH-1:2*DATA_WIDTH]    <= rd_0_data;
            end

            /*
             * 1- read flow 1 counters
             * 2- latch action flow 0 word 3
             */
            27: begin
               /* select the address for flow 1 */
               addr     <= EXACT_NUM_FLOW_WORDS_USED + (flow_1_index_0_match
                                                        ? {flow_1_index_0, 4'h0}
                                                        : {flow_1_index_1, 4'h0});
               rd_0_req <= 1'b1;

               exact_data[4*DATA_WIDTH-1:3*DATA_WIDTH]    <= rd_0_data;
            end

            /*
             * 1- read flow 1 action word 0
             * 2- latch action flow 0 word 4
             * 3- reset flow 0 control signals and set data vld for flow 0
             */
            28: begin
               rd_0_req                                   <= 1'b1;

               exact_data[5*DATA_WIDTH-1:4*DATA_WIDTH]    <= rd_0_data;

               flow_0_vld                                 <= 0;
               exact_data_vld                             <= flow_0_vld;
            end

            /*
             * 1- read flow 1 action word 1
             * 2- no rd_0_vld since 5 cycles ago we updated the counters
             */
            29: begin
               rd_0_req  <= 1'b1;

               // synthesis translate_off
               if (rd_0_vld) begin
                  $display("%t %m ERROR: There should be no rd_0_vld since cntrs were written to SRAM, no rd req.", $time);
                  $stop;
               end
               // synthesis translate_on
            end

            /*
             * 1- read flow 1 action word 2
             * 2- 5 cycles ago, the SRAM arbiter was servicing a reg req so no vld data
             * 3- set exact hit/miss for flow 1
             */
            30: begin
               rd_0_req <= 1'b1;

               // synthesis translate_off
               if (rd_0_vld) begin
                  $display("%t %m ERROR: There should be no request ack since this is where the reg req becomes vld.", $time);
                  $stop;
               end
               // synthesis translate_on
            end

            /*
             * 1- read flow 1 action word 3
             * 2- 5 cycles ago, the SRAM arbiter was might have reset the counters so no vld data
             */
            31: begin
               rd_0_req                      <= 1'b1;

               // synthesis translate_off
               if (rd_0_vld) begin
                  $display("%t %m ERROR: There should be no request ack since this is where the counters where reset.", $time);
                  $stop;
               end
               // synthesis translate_on

               /* set the hit/miss for flow 1 */
               exact_hit   <= (flow_1_index_0_match===1'b1 || flow_1_index_1_match===1'b1) && flow_1_vld;
               exact_miss  <= !(flow_1_index_0_match===1'b1 || flow_1_index_1_match===1'b1) && flow_1_vld;
            end

         endcase // case(cycle_num)
      end // else: !if(reset)
   end // always @ (posedge clk)

endmodule // wildcard_match


