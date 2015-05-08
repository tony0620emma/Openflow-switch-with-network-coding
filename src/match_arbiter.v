///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id: match_arbiter.v 3648 2008-04-23 02:31:10Z jnaous $
//
// Module: match_arbiter.v
// Project: NF2.1 OpenFlow Switch
// Author: Jad Naous <jnaous@stanford.edu>
// Description: arbitrates between different sources of matches and selects
//  a winner. Currently exact always wins over wildcard.
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
`timescale 1ns/1ps

  module match_arbiter
    #(parameter ACTION_WIDTH = `OPENFLOW_ACTION_WIDTH)
    (input                                   wildcard_hit,
     input                                   wildcard_miss,
     input[ACTION_WIDTH-1:0]                 wildcard_data,
     input                                   wildcard_data_vld,
     output reg                              wildcard_wins,
     output reg                              wildcard_loses,

     input [`OPENFLOW_ENTRY_SRC_PORT_WIDTH-1:0] flow_entry_src_port,
     input                                      flow_entry_vld,

     input                                   exact_hit,
     input                                   exact_miss,
     input[ACTION_WIDTH-1:0]                 exact_data,
     input                                   exact_data_vld,
     output reg                              exact_wins,
     output reg                              exact_loses,

     output reg                              result_fifo_wr_en,
     output reg [`OPENFLOW_ENTRY_SRC_PORT_WIDTH + ACTION_WIDTH-1:0] result_fifo_din,

     input                                   reset,
     input                                   clk);

   //-------------------- Internal Parameters ------------------------
   localparam  WAIT_FOR_WILDCARD    = 0,
               WAIT_FOR_EXACT       = 1,
               WAIT_FOR_EXACT_DATA  = 2;

   //------------------------ Wires/Regs -----------------------------
   reg [1:0]                                 state;

   reg [`OPENFLOW_ENTRY_SRC_PORT_WIDTH-1:0]  flow_entry_src_port_latched;

   reg                                       fifo_rd_en;

   wire [ACTION_WIDTH-1:0]                   dout_wildcard_data;
   wire [`OPENFLOW_ENTRY_SRC_PORT_WIDTH-1:0] dout_flow_entry_src_port;
   //-------------------------- Modules ------------------------------

   small_fifo
     #(.WIDTH(1+ACTION_WIDTH+`OPENFLOW_ENTRY_SRC_PORT_WIDTH),
       .MAX_DEPTH_BITS(2))
      wildcard_results_fifo
        (.din           ({wildcard_hit, wildcard_data, flow_entry_src_port_latched}),
         .wr_en         (wildcard_data_vld),
         .rd_en         (fifo_rd_en),
         .dout          ({dout_wildcard_hit, dout_wildcard_data, dout_flow_entry_src_port}),
         .full          (),
         .nearly_full   (),
         .empty         (flow_fifo_empty),
         .reset         (reset),
         .clk           (clk)
         );

   //--------------------------- Logic -------------------------------

   /* The following assumptions are made:
    *  - The wildcard data and data_vld always arrive together
    *  - The wildcard data_vld/miss/hit signals always arrive at least one cycle
    *    before the exact data_vld/hit/miss.
    *  - The exact data_vld signal arrives at least one cycle after
    *    the exact hit/miss
    */
   always @(posedge clk) begin
      if(reset) begin
         state                <= WAIT_FOR_WILDCARD;
         fifo_rd_en           <= 0;
         exact_wins           <= 0;
         exact_loses          <= 0;
         result_fifo_wr_en    <= 0;
         result_fifo_din      <= 0;
         wildcard_wins        <= 0;
         wildcard_loses       <= 0;
         flow_entry_src_port_latched <= 0;
      end // if (reset)
      else begin
         fifo_rd_en           <= 0;
         exact_wins           <= 0;
         exact_loses          <= 0;
         result_fifo_wr_en    <= 0;
         result_fifo_din      <= {dout_flow_entry_src_port,
                                  {ACTION_WIDTH{1'b0}}};
         wildcard_wins        <= 0;
         wildcard_loses       <= 0;

         if(flow_entry_vld) begin
            flow_entry_src_port_latched <= flow_entry_src_port;
         end

         case (state)
            WAIT_FOR_WILDCARD: begin
               if(!flow_fifo_empty) begin
                  fifo_rd_en    <= 1;
                  state         <= WAIT_FOR_EXACT;
               end
            end

            WAIT_FOR_EXACT: begin
               if(exact_hit || exact_miss) begin
                  if(exact_hit) begin
                     state              <= WAIT_FOR_EXACT_DATA;
                     exact_wins         <= 1;
                     wildcard_loses     <= 1;
                  end
                  else if(dout_wildcard_hit) begin
                     wildcard_wins 	  <= 1;
                     exact_loses 	  <= 1;
                     result_fifo_wr_en 	  <= 1;
                     result_fifo_din 	  <= {dout_flow_entry_src_port,
                                              dout_wildcard_data};
		     state                <= WAIT_FOR_WILDCARD;
                  end
                  else begin
                     exact_loses          <= 1;
                     wildcard_loses       <= 1;
                     result_fifo_wr_en    <= 1;
                     result_fifo_din      <= {dout_flow_entry_src_port,
                                              {ACTION_WIDTH{1'b0}}};
		     state                <= WAIT_FOR_WILDCARD;
                  end // else: !if(dout_wildcard_hit)
               end // if (exact_hit || exact_miss)
            end // case: WAIT_FOR_EXACT

            WAIT_FOR_EXACT_DATA: begin
               if(exact_data_vld) begin
		  if(!flow_fifo_empty) begin
		     fifo_rd_en    <= 1;
		     state         <= WAIT_FOR_EXACT;
		  end
		  else begin
		     state         <= WAIT_FOR_WILDCARD;
		  end
                  result_fifo_wr_en    <= 1;
                  result_fifo_din      <= {dout_flow_entry_src_port,
                                           exact_data};
               end
            end

         endcase // case(state)
      end // else: !if(reset)
   end // always @ (posedge clk)
endmodule
