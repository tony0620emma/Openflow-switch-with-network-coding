///////////////////////////////////////////////////////////////////////////////
// $Id: wildcard_match.v 5697 2009-06-17 22:32:11Z tyabe $
//
// Module: wildcard_match.v
// Project: NF2.1 OpenFlow Switch
// Author: Jad Naous <jnaous@stanford.edu>
// Description: matches a flow entry allowing a wildcard
//   Uses a register block to maintain counters associated with the table
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


  module wildcard_match
    #(parameter NUM_OUTPUT_QUEUES = 8,                  // obvious
      parameter PKT_SIZE_WIDTH = 12,                    // number of bits for pkt size
      parameter UDP_REG_SRC_WIDTH = 2                   // identifies which module started this request
      )
   (// --- Interface for lookups
    input [`OPENFLOW_ENTRY_WIDTH-1:0]      flow_entry,
    input                                  flow_entry_vld,
    input [PKT_SIZE_WIDTH-1:0]             pkt_size,
    output                                 wildcard_match_rdy,

    // --- Interface to arbiter
    output                                 wildcard_hit,
    output                                 wildcard_miss,
    output [`OPENFLOW_ACTION_WIDTH-1:0]    wildcard_data,
    output                                 wildcard_data_vld,
    input                                  wildcard_wins,
    input                                  wildcard_loses,

    // --- Interface to registers
    input                                  reg_req_in,
    input                                  reg_ack_in,
    input                                  reg_rd_wr_L_in,
    input  [`UDP_REG_ADDR_WIDTH-1:0]       reg_addr_in,
    input  [`CPCI_NF2_DATA_WIDTH-1:0]      reg_data_in,
    input  [UDP_REG_SRC_WIDTH-1:0]         reg_src_in,

    output                                 reg_req_out,
    output                                 reg_ack_out,
    output                                 reg_rd_wr_L_out,
    output     [`UDP_REG_ADDR_WIDTH-1:0]   reg_addr_out,
    output     [`CPCI_NF2_DATA_WIDTH-1:0]  reg_data_out,
    output     [UDP_REG_SRC_WIDTH-1:0]     reg_src_out,

    // --- Interface to Watchdog Timer
    input                                  table_flush,

    // --- Misc
    input [31:0]                           openflow_timer,
    input                                  reset,
    input                                  clk
   );

   `LOG2_FUNC
   `CEILDIV_FUNC

   //-------------------- Internal Parameters ------------------------
   localparam WILDCARD_NUM_DATA_WORDS_USED = `OPENFLOW_WILDCARD_NUM_DATA_WORDS_USED;
   localparam WILDCARD_NUM_CMP_WORDS_USED  = `OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED;
   localparam WILDCARD_NUM_REGS_USED = (2 // for the read and write address registers
                                        + `OPENFLOW_WILDCARD_NUM_DATA_WORDS_USED // for data associated with an entry
                                        + `OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED  // for the data to match on
                                        + `OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED  // for the don't cares
                                        );

   localparam LUT_DEPTH_BITS = log2(`OPENFLOW_WILDCARD_TABLE_SIZE);

   localparam SIMULATION = 0
	      // synthesis translate_off
	      || 1
	      // synthesis translate_on
	      ;


   //---------------------- Wires and regs----------------------------
   wire                                                      cam_busy;
   wire                                                      cam_match;
   wire [`OPENFLOW_WILDCARD_TABLE_SIZE-1:0]                  cam_match_addr;
   wire [`OPENFLOW_ENTRY_WIDTH-1:0]                          cam_cmp_din, cam_cmp_data_mask;
   wire [`OPENFLOW_ENTRY_WIDTH-1:0]                          cam_din, cam_data_mask;
   wire                                                      cam_we;
   wire [LUT_DEPTH_BITS-1:0]                                 cam_wr_addr;

   wire [WILDCARD_NUM_CMP_WORDS_USED-1:0]                    cam_busy_ind;
   wire [WILDCARD_NUM_CMP_WORDS_USED-1:0]                    cam_match_ind;
   wire [WILDCARD_NUM_CMP_WORDS_USED-1:0]                    cam_match_addr_ind[`OPENFLOW_WILDCARD_TABLE_SIZE-1:0];
   wire [31:0]                                               cam_cmp_din_ind[WILDCARD_NUM_CMP_WORDS_USED-1:0];
   wire [31:0]                                               cam_cmp_data_mask_ind[WILDCARD_NUM_CMP_WORDS_USED-1:0];
   wire [31:0]                                               cam_din_ind[WILDCARD_NUM_CMP_WORDS_USED-1:0];
   wire [31:0]                                               cam_data_mask_ind[WILDCARD_NUM_CMP_WORDS_USED-1:0];

   wire [`UDP_REG_ADDR_WIDTH-1:0]                            cam_reg_addr_out;
   wire [`CPCI_NF2_DATA_WIDTH-1:0]                           cam_reg_data_out;
   wire [UDP_REG_SRC_WIDTH-1:0]                              cam_reg_src_out;

   wire [LUT_DEPTH_BITS-1:0]                                 wildcard_address;
   wire [LUT_DEPTH_BITS-1:0]                                 dout_wildcard_address;

   reg [`OPENFLOW_WILDCARD_TABLE_SIZE-1:0]                   wildcard_hit_address_decoded;
   wire [`OPENFLOW_WILDCARD_TABLE_SIZE*PKT_SIZE_WIDTH - 1:0] wildcard_hit_address_decoded_expanded;
   wire [`OPENFLOW_WILDCARD_TABLE_SIZE*PKT_SIZE_WIDTH - 1:0] wildcard_entry_hit_byte_size;
   wire [`OPENFLOW_WILDCARD_TABLE_SIZE*32 - 1:0]             wildcard_entry_last_seen_timestamps;

   wire [PKT_SIZE_WIDTH-1:0]                                 dout_pkt_size;

   reg [PKT_SIZE_WIDTH-1:0]                                  wildcard_entry_hit_byte_size_word [`OPENFLOW_WILDCARD_TABLE_SIZE-1:0];
   reg [31:0]                                                wildcard_entry_last_seen_timestamps_words[`OPENFLOW_WILDCARD_TABLE_SIZE-1:0];

   integer                                                   i;

   //------------------------- Modules -------------------------------
   assign wildcard_match_rdy = 1;

   unencoded_cam_lut_sm
     #(.CMP_WIDTH (`OPENFLOW_ENTRY_WIDTH),
       .DATA_WIDTH (`OPENFLOW_ACTION_WIDTH),
       .LUT_DEPTH  (`OPENFLOW_WILDCARD_TABLE_SIZE),
       .TAG (`OPENFLOW_WILDCARD_LOOKUP_BLOCK_ADDR),
       .REG_ADDR_WIDTH (`OPENFLOW_WILDCARD_LOOKUP_REG_ADDR_WIDTH))
       wildcard_cam_lut_sm
         (// --- Interface for lookups
          .lookup_req          (flow_entry_vld),
          .lookup_cmp_data     (flow_entry),
          .lookup_cmp_dmask    ({`OPENFLOW_ENTRY_WIDTH{1'b0}}),
          .lookup_ack          (wildcard_data_vld),
          .lookup_hit          (wildcard_hit),
          .lookup_data         (wildcard_data),
          .lookup_address      (wildcard_address),

          // --- Interface to registers
          .reg_req_in          (reg_req_in),
          .reg_ack_in          (reg_ack_in),
          .reg_rd_wr_L_in      (reg_rd_wr_L_in),
          .reg_addr_in         (reg_addr_in),
          .reg_data_in         (reg_data_in),
          .reg_src_in          (reg_src_in),

          .reg_req_out         (cam_reg_req_out),
          .reg_ack_out         (cam_reg_ack_out),
          .reg_rd_wr_L_out     (cam_reg_rd_wr_L_out),
          .reg_addr_out        (cam_reg_addr_out),
          .reg_data_out        (cam_reg_data_out),
          .reg_src_out         (cam_reg_src_out),

          // --- CAM interface
          .cam_busy            (cam_busy),
          .cam_match           (cam_match),
          .cam_match_addr      (cam_match_addr),
          .cam_cmp_din         (cam_cmp_din),
          .cam_din             (cam_din),
          .cam_we              (cam_we),
          .cam_wr_addr         (cam_wr_addr),
          .cam_cmp_data_mask   (cam_cmp_data_mask),
          .cam_data_mask       (cam_data_mask),

          // --- Watchdog Timer Interface
          .table_flush         (table_flush),

          // --- Misc
          .reset               (reset),
          .clk                 (clk));

   /* Split up the CAM into multiple smaller CAMs to improve timing */
   generate
      genvar ii,j;
      for (ii=0; ii<WILDCARD_NUM_CMP_WORDS_USED; ii=ii+1) begin:gen_cams
         wire [`OPENFLOW_WILDCARD_TABLE_SIZE-1:0] cam_match_addr_temp;
         srl_cam_unencoded_32x32 openflow_cam
           (
            // Outputs
            .busy                             (cam_busy_ind[ii]),
            .match                            (cam_match_ind[ii]),
            .match_addr                       (cam_match_addr_temp),
            // Inputs
            .clk                              (clk),
            .cmp_din                          (cam_cmp_din_ind[ii]),
            .din                              (cam_din_ind[ii]),
            .cmp_data_mask                    (cam_cmp_data_mask_ind[ii]),
            .data_mask                        (cam_data_mask_ind[ii]),
            .we                               (cam_we),
            .wr_addr                          (cam_wr_addr)
            );
         if(ii < WILDCARD_NUM_CMP_WORDS_USED - 1) begin
            assign cam_cmp_din_ind[ii]         = cam_cmp_din[32*ii + 31: 32*ii];
            assign cam_din_ind[ii]             = cam_din[32*ii + 31: 32*ii];
            assign cam_cmp_data_mask_ind[ii]   = cam_cmp_data_mask[32*ii + 31: 32*ii];
            assign cam_data_mask_ind[ii]       = cam_data_mask[32*ii + 31: 32*ii];
            assign cam_cmp_din_ind[ii]         = cam_cmp_din[32*ii + 31: 32*ii];
         end
         else begin
            assign cam_cmp_din_ind[ii]         = cam_cmp_din[`OPENFLOW_ENTRY_WIDTH-1: 32*ii];
            assign cam_din_ind[ii]             = cam_din[`OPENFLOW_ENTRY_WIDTH-1: 32*ii];
            assign cam_cmp_data_mask_ind[ii]   = cam_cmp_data_mask[`OPENFLOW_ENTRY_WIDTH-1: 32*ii];
            assign cam_data_mask_ind[ii]       = cam_data_mask[`OPENFLOW_ENTRY_WIDTH-1: 32*ii];
            assign cam_cmp_din_ind[ii]         = cam_cmp_din[`OPENFLOW_ENTRY_WIDTH-1: 32*ii];
         end // else: !if(ii < WILDCARD_NUM_CMP_WORDS_USED - 1)

         for (j=0; j<`OPENFLOW_WILDCARD_TABLE_SIZE; j=j+1) begin:gen_match_addr_mem
            assign cam_match_addr_ind[j][ii] = cam_match_addr_temp[j];
         end
      end // block: gen_cams

      for (ii=0; ii<`OPENFLOW_WILDCARD_TABLE_SIZE; ii=ii+1) begin:gen_match_addr
         assign cam_match_addr[ii] = &cam_match_addr_ind[ii];
      end
   endgenerate

   assign cam_busy  = |cam_busy_ind;
   assign cam_match = |cam_match_addr;

   generic_regs
     #(.UDP_REG_SRC_WIDTH (UDP_REG_SRC_WIDTH),
       .TAG (`OPENFLOW_WILDCARD_LOOKUP_BLOCK_ADDR),
       .REG_ADDR_WIDTH (`OPENFLOW_WILDCARD_LOOKUP_REG_ADDR_WIDTH),
       .NUM_COUNTERS (`OPENFLOW_WILDCARD_TABLE_SIZE  // for number of bytes
                      +`OPENFLOW_WILDCARD_TABLE_SIZE // for number of packets
                      ),
       /*****************
	* JN: FIXME For now we will reset on read during simulation only
	*****************/
       .RESET_ON_READ (SIMULATION),
       .NUM_SOFTWARE_REGS (2),
       .NUM_HARDWARE_REGS (`OPENFLOW_WILDCARD_TABLE_SIZE), // for last seen timestamps
       .COUNTER_INPUT_WIDTH (PKT_SIZE_WIDTH), // max pkt size
       .REG_START_ADDR (WILDCARD_NUM_REGS_USED) // used for the access to the cam/lut
       )
   generic_regs
     (
      .reg_req_in        (cam_reg_req_out),
      .reg_ack_in        (cam_reg_ack_out),
      .reg_rd_wr_L_in    (cam_reg_rd_wr_L_out),
      .reg_addr_in       (cam_reg_addr_out),
      .reg_data_in       (cam_reg_data_out),
      .reg_src_in        (cam_reg_src_out),

      .reg_req_out       (reg_req_out),
      .reg_ack_out       (reg_ack_out),
      .reg_rd_wr_L_out   (reg_rd_wr_L_out),
      .reg_addr_out      (reg_addr_out),
      .reg_data_out      (reg_data_out),
      .reg_src_out       (reg_src_out),

      // --- counters interface
      .counter_updates   ({wildcard_hit_address_decoded_expanded,
                           wildcard_entry_hit_byte_size}
                          ),
      .counter_decrement ({(2*`OPENFLOW_WILDCARD_TABLE_SIZE){1'b0}}),

      // --- SW regs interface
      .software_regs     (),

      // --- HW regs interface
      .hardware_regs     ({wildcard_entry_last_seen_timestamps}),

      .clk               (clk),
      .reset             (reset));

   /* we might receive four input packets simultaneously from ethernet. In addition,
    * we might receive a pkt from DMA. So we need at least 5 spots. */
   fallthrough_small_fifo
     #(.WIDTH(PKT_SIZE_WIDTH),
       .MAX_DEPTH_BITS(3))
      pkt_size_fifo
        (.din           (pkt_size),
         .wr_en         (flow_entry_vld),
         .rd_en         (fifo_rd_en),
         .dout          (dout_pkt_size),
         .full          (),
         .nearly_full   (),
         .empty         (pkt_size_fifo_empty),
         .reset         (reset),
         .clk           (clk)
         );

   fallthrough_small_fifo
     #(.WIDTH(LUT_DEPTH_BITS),
       .MAX_DEPTH_BITS(3))
      address_fifo
        (.din           (wildcard_address),
         .wr_en         (wildcard_data_vld),
         .rd_en         (fifo_rd_en),
         .dout          (dout_wildcard_address),
         .full          (),
         .nearly_full   (),
         .empty         (address_fifo_empty),
         .reset         (reset),
         .clk           (clk)
         );

   //-------------------------- Logic --------------------------------
   assign wildcard_miss = wildcard_data_vld & !wildcard_hit;
   assign fifo_rd_en = wildcard_wins || wildcard_loses;

   /* update the generic register interface if wildcard matching
    * wins the arbitration */
   always @(*) begin
      wildcard_hit_address_decoded = 0;
      for(i=0; i<`OPENFLOW_WILDCARD_TABLE_SIZE; i=i+1) begin
         wildcard_entry_hit_byte_size_word[i] = 0;
      end
      if(wildcard_wins) begin
         wildcard_hit_address_decoded[dout_wildcard_address] = 1;
         wildcard_entry_hit_byte_size_word[dout_wildcard_address]
           = dout_pkt_size;
      end
   end // always @ (*)

   generate
      genvar gi;
      for(gi=0; gi<`OPENFLOW_WILDCARD_TABLE_SIZE; gi=gi+1) begin:concat
         assign wildcard_entry_hit_byte_size[gi*PKT_SIZE_WIDTH +: PKT_SIZE_WIDTH]
                = wildcard_entry_hit_byte_size_word[gi];
         assign wildcard_entry_last_seen_timestamps[gi*32 +: 32]
                = wildcard_entry_last_seen_timestamps_words[gi];
         assign wildcard_hit_address_decoded_expanded[gi*PKT_SIZE_WIDTH +: PKT_SIZE_WIDTH]
                ={{(PKT_SIZE_WIDTH-1){1'b0}}, wildcard_hit_address_decoded[gi]};
      end
   endgenerate

   // update the timestamp of the entry
   always @(posedge clk) begin
      if(cam_we) begin
         wildcard_entry_last_seen_timestamps_words[cam_wr_addr] <= openflow_timer;
      end
      else if(wildcard_wins) begin
         wildcard_entry_last_seen_timestamps_words[dout_wildcard_address] <= openflow_timer;
      end
   end // always @ (posedge clk)

endmodule // wildcard_match


