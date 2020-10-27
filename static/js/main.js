//datepicker

$( function() {
    $( "#channeldate" ).datepicker({
      dateFormat: "dd/mm/yy"
    });

    $( "#channelenddate" ).datepicker({
      dateFormat: "dd/mm/yy"
    });

    $( "#sessiondate" ).datepicker({
      dateFormat: "dd/mm/yy"
    });


    // $('#starttime').on("input change", function() {
    //     //make sure user can only input 4 numbers
    //     if ($(this).val().length > 4) {
    //         this.value = $(this).val().slice(0,4);
    //     }
    //
    //     var starttime = $(this).val()
    //     var starttime_validator = moment(starttime, "HHHH", true).isValid();
    //
    //     if (!starttime_validator) {
    //         $('#starttimeHelp').text('Please enter time in HHHH format.');
    //         $('#channel-submit-btn').prop('disabled', true);
    //     } else {
    //         $('#channel-submit-btn').prop('disabled', false);
    //     }
    // });

    // $('#endtime').on("input change", function() {
    //     //make sure user can only input 4 numbers
    //     if ($(this).val().length > 4) {
    //         this.value = $(this).val().slice(0,4);
    //     }
    //
    //     var starttime = $('#starttime').val()
    //     var endtime = $(this).val()
    //     var endtime_validator = moment(endtime, "HHHH", true).isValid();
    //     var endtimeafter_validator = moment(endtime).isAfter(starttime);
    //
    //     if (!endtime_validator) {
    //         $('#channel-submit-btn').prop('disabled', true);
    //     } else {
    //         if (!endtimeafter_validator) {
    //             $('#channel-submit-btn').prop('disabled', true);
    //         } else {
    //             $('#channel-submit-btn').prop('disabled', false);
    //         }
    //     }
    //
    // })
} );